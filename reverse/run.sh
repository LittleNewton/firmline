#!/usr/bin/env bash
# usage: ./run.sh FILE GHIDRA_ARCH RESULTS_DIR [BASE]
die() { printf '%s\n' "$1" >&2 && exit 1; }

[ -n "$TIMEOUT_TERM" ] || die '$TIMEOUT_TERM not set in environment, should be timeout to terminate in seconds.'
[ -n "$TIMEOUT_KILL" ] || die '$TIMEOUT_KILL not set in environment, should be timeout to kill after termination in seconds.'

[ $# -ge 3 ] || die 'Not enough arguments.'

[ -z "$GHIDRA_HOME" ] && die 'GHIDRA_HOME is not set.'
headless="$GHIDRA_HOME"/support/analyzeHeadless
[ -f "$headless" ] || die "$headless does not exist."
[ -x "$headless" ] || die "$headless is not executable."

fwfile="$1"
architecture="$2"
[ -f "$fwfile" ] || die "File $fwfile is not readable."
shasum="$(sha256sum "$fwfile" | cut -d' ' -f1)"

results_dir="$3"

base=""
[ $# -eq 4 ] && base="$4"

GHIDRA_PROJ_DIR="headless-project-$RANDOM"
GHIDRA_PROJ_NAME=firmware
mkdir -p "$GHIDRA_PROJ_DIR"

timeout --kill-after=$TIMEOUT_KILL $TIMEOUT_TERM "$headless" "$GHIDRA_PROJ_DIR" $GHIDRA_PROJ_NAME -processor "$architecture" -import "$fwfile" -noanalysis
res=$?
if [ $res -eq 0 ]; then
  timeout --kill-after=$TIMEOUT_KILL $TIMEOUT_TERM "$headless" "$GHIDRA_PROJ_DIR" $GHIDRA_PROJ_NAME -process "$(basename "$fwfile")" -scriptPath . -postScript "ghidra_analyze.py" "$shasum" "$results_dir" "$base"
  res=$?
fi
rm -r "$GHIDRA_PROJ_DIR"
exit $res
