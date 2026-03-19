"""Run Ghidra analysis via pyghidra and extract features from a binary."""

import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

from .features import enrich_feature_set


def _find_ghidra_install() -> str:
    """Locate Ghidra install directory."""
    import glob
    candidates = [
        os.environ.get("GHIDRA_INSTALL_DIR", ""),
    ]
    candidates += glob.glob(os.path.expanduser("~/ghidra_*/"))
    candidates += glob.glob("/opt/ghidra*/")
    candidates += glob.glob("/Applications/ghidra*/")
    for c in candidates:
        if c and os.path.isdir(c):
            return c
    return ""


def _binary_metadata(binary_path: str) -> dict:
    stat = os.stat(binary_path)
    return {
        "path": os.path.abspath(binary_path),
        "size": stat.st_size,
        "mtime": int(stat.st_mtime),
    }


def _load_cached_features(output_path: str, binary_path: str) -> dict | None:
    if not os.path.isfile(output_path):
        return None
    try:
        with open(output_path) as f:
            data = json.load(f)
    except Exception:
        return None
    if data.get("source_metadata") == _binary_metadata(binary_path):
        return data
    return None


def _extract_features(program) -> dict:
    """Extract per-function features from a Ghidra FlatProgramAPI program."""
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    listing = program.getListing()
    func_mgr = program.getFunctionManager()
    bbm = BasicBlockModel(program)
    ref_mgr = program.getReferenceManager()

    functions_out = []
    functions = list(func_mgr.getFunctions(True))
    total_funcs = len(functions)

    print(f"Extracting features from {total_funcs} discovered functions...", flush=True)

    for idx, func in enumerate(functions, 1):
        if func.isThunk():
            continue

        if idx == 1 or idx % 100 == 0 or idx == total_funcs:
            print(f"  [{idx}/{total_funcs}] {func.getName()}", flush=True)

        name = func.getName()
        entry = func.getEntryPoint().toString()
        body = func.getBody()

        # --- instruction-level features ---
        mnemonic_hist = Counter()
        bigrams = Counter()
        instr_count = 0
        constants = set()
        prev_mnemonic = None

        instr_iter = listing.getInstructions(body, True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            m = instr.getMnemonicString()
            mnemonic_hist[m] += 1
            instr_count += 1
            if prev_mnemonic is not None:
                bigrams[prev_mnemonic + "," + m] += 1
            prev_mnemonic = m
            # collect scalar operand constants
            for i in range(instr.getNumOperands()):
                for obj in instr.getOpObjects(i):
                    cls_name = type(obj).__name__
                    if cls_name in ("Scalar", "int", "long") or hasattr(obj, 'longValue'):
                        try:
                            v = int(obj.longValue()) if hasattr(obj, 'longValue') else int(obj)
                            if 2 <= abs(v) <= 0xFFFFFFFF:
                                constants.add(v)
                        except Exception:
                            pass

        # --- basic-block count ---
        block_count = 0
        block_iter = bbm.getCodeBlocksContaining(body, monitor)
        while block_iter.hasNext():
            block_iter.next()
            block_count += 1

        # --- referenced strings ---
        # Iterate instructions in the function body and inspect only references
        # originating from those instructions. This avoids walking most of the
        # program's global reference table once per function.
        strings = []
        seen_strings = set()
        instr_iter = listing.getInstructions(body, True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            refs = ref_mgr.getReferencesFrom(instr.getAddress())
            for ref in refs:
                to_addr = ref.getToAddress()
                data = listing.getDataAt(to_addr)
                if data is not None and data.hasStringValue():
                    s = data.getValue()
                    s = str(s) if s is not None else ""
                    if len(s) >= 2 and s not in seen_strings:
                        seen_strings.add(s)
                        strings.append(s)

        # --- called functions ---
        called_funcs = []
        called_set = func.getCalledFunctions(monitor)
        for cf in called_set:
            called_funcs.append({
                "name": cf.getName(),
                "is_external": cf.isExternal() or cf.isThunk(),
                "entry": None if (cf.isExternal() or cf.isThunk()) else cf.getEntryPoint().toString(),
            })

        # --- calling functions ---
        callers = []
        caller_set = func.getCallingFunctions(monitor)
        for cf in caller_set:
            callers.append(cf.getName())

        func_data = {
            "name": name,
            "entry": entry,
            "size": int(body.getNumAddresses()),
            "instr_count": instr_count,
            "block_count": block_count,
            "mnemonic_hist": dict(mnemonic_hist),
            "mnemonic_bigrams": dict(bigrams),
            "strings": strings,
            "constants": list(constants),
            "called_functions": called_funcs,
            "callers": callers,
        }
        functions_out.append(func_data)

    return enrich_feature_set({
        "binary": str(program.getExecutablePath()),
        "arch": str(program.getLanguage().getProcessor()),
        "num_functions": len(functions_out),
        "functions": functions_out,
    })


def run_extract(binary_path: str, output_path: str, ghidra_path: str | None = None,
                reuse_cached: bool = True) -> dict:
    """Run Ghidra via pyghidra to extract features from binary_path into output_path.

    Returns the parsed features dict.
    """
    binary_path = os.path.abspath(binary_path)
    output_path = os.path.abspath(output_path)

    if not os.path.isfile(binary_path):
        print(f"Error: binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    if reuse_cached:
        cached = _load_cached_features(output_path, binary_path)
        if cached is not None:
            print(f"Reusing cached features from {output_path}")
            return cached

    ghidra_install = ghidra_path or _find_ghidra_install()
    if not ghidra_install:
        print(
            "Error: cannot find Ghidra. Set GHIDRA_INSTALL_DIR env var.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        import pyghidra
    except ImportError:
        print("Error: pyghidra not installed. Run: pip install pyghidra", file=sys.stderr)
        sys.exit(1)

    print(f"Running Ghidra analysis on {binary_path} ...")
    print("Waiting for Ghidra auto-analysis to finish, then extracting per-function features...", flush=True)

    project_parent = os.path.dirname(output_path) or tempfile.gettempdir()
    project_name = f"{Path(binary_path).stem}_ghidra"
    settings_root = os.path.join(project_parent, ".ghidra-settings")
    os.makedirs(settings_root, exist_ok=True)

    existing_java_tool_opts = os.environ.get("JAVA_TOOL_OPTIONS", "")
    settings_opt = f"-Dapplication.settingsdir={settings_root}"
    if settings_opt not in existing_java_tool_opts:
        os.environ["JAVA_TOOL_OPTIONS"] = f"{settings_opt} {existing_java_tool_opts}".strip()

    pyghidra.start(ghidra_install)

    with tempfile.TemporaryDirectory(prefix=f"{project_name}_", dir=project_parent) as tmp_project_root:
        try:
            with pyghidra.open_program(
                binary_path,
                project_location=tmp_project_root,
                project_name=project_name,
            ) as flat_api:
                program = flat_api.getCurrentProgram()
                data = _extract_features(program)
        except KeyboardInterrupt:
            print("\nPatchTriage extraction interrupted by user.", file=sys.stderr)
            raise SystemExit(130)
        except BaseException as exc:
            # If the user interrupts while pyghidra is unwinding its context manager,
            # JPype can surface JVMNotRunning during cleanup instead of the original
            # KeyboardInterrupt. Treat that as a normal cancellation path.
            if exc.__class__.__name__ == "JVMNotRunning":
                print("\nPatchTriage extraction interrupted during Ghidra cleanup.", file=sys.stderr)
                raise SystemExit(130)
            raise

    data["source_metadata"] = _binary_metadata(binary_path)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    print(f"Extracted {data['num_functions']} functions -> {output_path}")
    return data
