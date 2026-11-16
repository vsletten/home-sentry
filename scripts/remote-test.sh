#!/usr/bin/env bash
# Cross-platform check on a machine you own, over SSH:
#   sync this worktree -> run the test suite there -> run a live probe there ->
#   pull the probe back -> diff it against the local inventory (the answer key).
#
#   scripts/remote-test.sh macbot-zero            # tests + probe without ports
#   scripts/remote-test.sh macbot-zero --ports    # also the port/service scan
#
# Nothing is installed system-wide on the remote: the code goes to ~/homesentry-build and
# Python comes from uv (needs uv on the remote). The remote never gets an inventory: the probe
# stores nothing, and HOMESENTRY_HOME points at a throwaway dir there.
# The answer key is compared from a SQLite backup copy, never the live database.
# Env: SSH_AGENT_SOCK (IdentityAgent), HS_REMOTE_DIR (default homesentry-build).
set -euo pipefail
host=${1:?usage: remote-test.sh <ssh-host> [--ports]}
shift
probe_args=("$@")
here=$(cd "$(dirname "$0")/.." && pwd)
rdir=${HS_REMOTE_DIR:-homesentry-build}
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10)
[[ -n "${SSH_AGENT_SOCK:-}" ]] && ssh_opts+=(-o "IdentityAgent=$SSH_AGENT_SOCK")
out=${HS_OUT:-${TMPDIR:-/tmp}/hs-remote-$host-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$out" && chmod 700 "$out"

echo "== sync -> $host:~/$rdir"
(cd "$here" && git ls-files -co --exclude-standard -z) |
  rsync -a --delete --from0 --files-from=- -e "ssh ${ssh_opts[*]}" "$here/" "$host:$rdir/"

remote() { ssh "${ssh_opts[@]}" "$host" "export PATH=\$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:\$PATH; cd ~/$rdir && $*"; }

echo "== remote environment"
remote 'uname -sm; sw_vers -productVersion 2>/dev/null || true; uv --version'

echo "== tests on $host"
remote 'nice -n 10 uv sync -q -p 3.13 && HOMESENTRY_HOME=$(mktemp -d) nice -n 10 uv run pytest -q -p no:cacheprovider 2>&1 | tail -4' |
  tee "$out/pytest.txt"

echo "== live probe on $host ${probe_args[*]:-}"
set +e
remote "HOMESENTRY_HOME=\$(mktemp -d) nice -n 10 uv run homesentry probe --json ${probe_args[*]:-}" >"$out/probe.json"
rc=$?
set -e
echo "probe exit $rc ($(wc -c <"$out/probe.json") bytes)"

echo "== compare against the answer key"
key=$out/key
mkdir -p "$key"
python3 - "${HOMESENTRY_HOME:-$HOME/.local/share/homesentry}/inventory.db" "$key/inventory.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
dst = sqlite3.connect(sys.argv[2]); src.backup(dst); dst.close()
PY
(cd "$here" && HOMESENTRY_HOME=$key uv run homesentry compare "$out/probe.json") | tee "$out/compare.txt"
rm -f "$key/inventory.db"* # private data: keep the diff, not the copy
echo "== results in $out"
