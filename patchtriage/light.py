"""Lightweight, non-Ghidra feature extraction backend."""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections import Counter

from .classify import classify_binary
from .features import enrich_feature_set
from .normalize import classify_api_family


def _run_text(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except Exception:
        return ""


def _source_metadata(binary_path: str) -> dict:
    stat = os.stat(binary_path)
    return {
        "path": os.path.abspath(binary_path),
        "size": stat.st_size,
        "mtime": int(stat.st_mtime),
    }


def _load_cached(output_path: str, binary_path: str) -> dict | None:
    if not os.path.isfile(output_path):
        return None
    try:
        with open(output_path) as f:
            data = json.load(f)
    except Exception:
        return None
    if data.get("source_metadata") == _source_metadata(binary_path):
        return data
    return None


def _extract_imports(binary_path: str) -> list[str]:
    out = _run_text(["nm", "-an", binary_path])
    imports = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "U":
            imports.append(parts[1])
        elif len(parts) >= 3 and parts[1] == "U":
            imports.append(parts[2])
    return sorted(set(imports))


def _extract_text_symbols(binary_path: str) -> list[dict]:
    out = _run_text(["nm", "-an", binary_path])
    symbols = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in {"T", "t"}:
            addr, _, name = parts[:3]
            symbols.append({"name": name, "entry": addr})
    return symbols


def _extract_strings(binary_path: str, limit: int = 400) -> list[str]:
    out = _run_text(["strings", "-a", binary_path])
    strings = []
    for line in out.splitlines():
        s = line.strip()
        if len(s) >= 4 and any(ch.isalpha() for ch in s):
            strings.append(s)
            if len(strings) >= limit:
                break
    return strings


def _detect_arch(binary_path: str) -> str:
    out = _run_text(["file", "-b", binary_path]).lower()
    if "arm64" in out or "aarch64" in out:
        return "aarch64"
    if "x86-64" in out or "x86_64" in out:
        return "x86_64"
    if "80386" in out or "i386" in out:
        return "x86"
    return "unknown"


def _extract_sections(binary_path: str, fmt: str) -> list[dict]:
    if fmt == "macho":
        return _extract_macho_sections(binary_path)
    return _extract_objdump_sections(binary_path)


def _extract_macho_sections(binary_path: str) -> list[dict]:
    out = _run_text(["otool", "-l", binary_path])
    sections = []
    current_seg = None
    section_name = None
    size = None
    attrs = set()
    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("segname "):
            current_seg = line.split(None, 1)[1]
        elif line.startswith("sectname "):
            section_name = line.split(None, 1)[1]
            size = None
            attrs = set()
        elif line.startswith("size ") and section_name:
            try:
                size = int(line.split()[1], 16)
            except Exception:
                size = 0
        elif line.startswith("flags ") and section_name:
            attrs.add(line.split()[-1].lower())
        elif section_name and line.startswith("reserved1 "):
            name = f"{current_seg}:{section_name}" if current_seg else section_name
            sections.append({
                "name": name,
                "size": size or 0,
                "is_executable": "__text" in name.lower() or "pure_instructions" in attrs,
                "is_data": "__data" in name.lower() or "__cstring" in name.lower(),
            })
            section_name = None
    return sections


def _extract_objdump_sections(binary_path: str) -> list[dict]:
    out = _run_text(["objdump", "-h", binary_path])
    sections = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 7 or not parts[0].isdigit():
            continue
        name = parts[1]
        try:
            size = int(parts[2], 16)
        except Exception:
            size = 0
        lower_name = name.lower()
        sections.append({
            "name": name,
            "size": size,
            "is_executable": any(tag in lower_name for tag in (".text", "text", "code")),
            "is_data": any(tag in lower_name for tag in (".data", ".rodata", ".bss", ".cstring", "data")),
        })
    return sections


def _extract_mnemonic_hist(binary_path: str, fmt: str, limit: int = 12000) -> tuple[dict[str, int], int]:
    if fmt == "macho":
        cmd = ["objdump", "--macho", "--disassemble", binary_path]
    else:
        cmd = ["objdump", "-d", binary_path]
    out = _run_text(cmd)
    hist: Counter[str] = Counter()
    total = 0
    for raw in out.splitlines():
        mnemonic = _parse_mnemonic(raw)
        if not mnemonic:
            continue
        hist[mnemonic] += 1
        total += 1
        if total >= limit:
            break
    return dict(hist), total


def _parse_mnemonic(line: str) -> str | None:
    if ":" not in line or "\t" not in line:
        return None
    _, rest = line.split(":", 1)
    parts = [part.strip() for part in rest.split("\t") if part.strip()]
    for part in parts:
        candidate = part.split()[0].lower()
        if re.fullmatch(r"[0-9a-f]+", candidate):
            continue
        if re.fullmatch(r"[a-z][a-z0-9._]*", candidate):
            return candidate
    return None


def _group_import_families(imports: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for name in imports:
        family = classify_api_family(name) or "other"
        grouped.setdefault(family, []).append(name)
    return {family: sorted(set(names)) for family, names in grouped.items()}


def run_light_extract(binary_path: str, output_path: str, reuse_cached: bool = True) -> dict:
    """Extract coarse whole-binary features without Ghidra."""
    binary_path = os.path.abspath(binary_path)
    output_path = os.path.abspath(output_path)

    if reuse_cached:
        cached = _load_cached(output_path, binary_path)
        if cached is not None:
            print(f"Reusing cached light features from {output_path}")
            return cached

    info = classify_binary(binary_path)
    imports = _extract_imports(binary_path)
    text_symbols = _extract_text_symbols(binary_path)
    strings = _extract_strings(binary_path)
    sections = _extract_sections(binary_path, info["format"])
    mnemonic_hist, instr_count = _extract_mnemonic_hist(binary_path, info["format"])
    import_families = _group_import_families(imports)
    arch = _detect_arch(binary_path)

    functions = []
    for sym in text_symbols[:200]:
        functions.append({
            "name": sym["name"],
            "entry": sym["entry"],
            "size": 1,
            "instr_count": 0,
            "block_count": 1,
            "mnemonic_hist": {},
            "mnemonic_bigrams": {},
            "strings": [],
            "constants": [],
            "called_functions": [],
            "callers": [],
        })

    for section in sections[:64]:
        section_strings = [section["name"]]
        if section["is_executable"]:
            section_strings.append("executable section")
        if section["is_data"]:
            section_strings.append("data section")
        functions.append({
            "name": f"section:{section['name']}",
            "entry": f"section:{section['name']}",
            "size": section["size"],
            "instr_count": instr_count if section["is_executable"] else 0,
            "block_count": 1,
            "mnemonic_hist": mnemonic_hist if section["is_executable"] else {},
            "mnemonic_bigrams": {},
            "strings": section_strings,
            "constants": [],
            "called_functions": [],
            "callers": [],
        })

    for family, family_imports in sorted(import_families.items()):
        functions.append({
            "name": f"imports:{family}",
            "entry": f"imports:{family}",
            "size": len(family_imports),
            "instr_count": 0,
            "block_count": 1,
            "mnemonic_hist": {},
            "mnemonic_bigrams": {},
            "strings": family_imports[:40],
            "constants": [],
            "called_functions": [
                {"name": name, "is_external": True, "entry": None}
                for name in family_imports
            ],
            "callers": [],
        })

    functions.append({
        "name": "__binary__",
        "entry": "binary",
        "size": info["size_bytes"],
        "instr_count": instr_count,
        "block_count": 1,
        "mnemonic_hist": mnemonic_hist,
        "mnemonic_bigrams": {},
        "strings": strings,
        "constants": [],
        "called_functions": [{"name": name, "is_external": True, "entry": None} for name in imports],
        "callers": [],
    })

    data = enrich_feature_set({
        "binary": binary_path,
        "arch": arch,
        "num_functions": len(functions),
        "functions": functions,
    })
    data["source_metadata"] = _source_metadata(binary_path)
    data["analysis_profile"] = "light"
    data["classification"] = info
    data["backend"] = "light"

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    print(
        f"Light extraction summary: {len(text_symbols)} text symbols, "
        f"{len(sections)} sections, {len(imports)} imports, {len(strings)} strings"
    )
    print(f"Extracted {data['num_functions']} coarse feature nodes -> {output_path}")
    return data
