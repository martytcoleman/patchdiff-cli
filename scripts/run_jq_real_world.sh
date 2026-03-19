#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/tmp/jq-real-world}"
GHIDRA_DIR="${GHIDRA_INSTALL_DIR:-}"
PATCHTRIAGE_BIN="${PATCHTRIAGE_BIN:-python -m patchtriage.cli}"

mkdir -p "$OUT_DIR"

uname_s="$(uname -s)"
uname_m="$(uname -m)"

case "$uname_s" in
  Linux) os_name="linux" ;;
  Darwin) os_name="macos" ;;
  *)
    echo "Unsupported OS: $uname_s" >&2
    exit 1
    ;;
esac

case "$uname_m" in
  x86_64|amd64) arch_name="amd64" ;;
  arm64|aarch64) arch_name="arm64" ;;
  *)
    echo "Unsupported architecture: $uname_m" >&2
    exit 1
    ;;
esac

v1="1.7"
v2="1.7.1"
bin1="$OUT_DIR/jq-${v1}-${os_name}-${arch_name}"
bin2="$OUT_DIR/jq-${v2}-${os_name}-${arch_name}"
report_dir="$OUT_DIR/report"

url1="https://github.com/jqlang/jq/releases/download/jq-${v1}/jq-${os_name}-${arch_name}"
url2="https://github.com/jqlang/jq/releases/download/jq-${v2}/jq-${os_name}-${arch_name}"

echo "Downloading jq ${v1} from: $url1"
curl -L --fail -o "$bin1" "$url1"
chmod +x "$bin1"

echo "Downloading jq ${v2} from: $url2"
curl -L --fail -o "$bin2" "$url2"
chmod +x "$bin2"

mkdir -p "$report_dir"

cmd=($PATCHTRIAGE_BIN run "$bin1" "$bin2" -o "$report_dir" --stripped --top 15 --html)
if [[ -n "$GHIDRA_DIR" ]]; then
  cmd+=(--ghidra "$GHIDRA_DIR")
fi

echo "Running PatchTriage on jq ${v1} -> ${v2}"
"${cmd[@]}"

echo
echo "Artifacts written to: $report_dir"
echo "Primary report: $report_dir/report.md"
