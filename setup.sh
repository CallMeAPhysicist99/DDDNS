#!/bin/sh
# One-time setup on a new Linux / macOS / Raspberry Pi device, from the project folder:
#
#     sh setup.sh
#
# Creates the Python venv, installs the Python packages into it, and installs
# the sidecar's Node.js packages. Safe to run again (e.g. after an update).
# Needs Python 3.10+ (with the venv module: apt install python3-venv) and Node.js 18+.
set -e
cd "$(dirname "$0")"

command -v node >/dev/null || { echo "Node.js 18 or newer is needed: https://nodejs.org" >&2; exit 1; }
[ -x venv/bin/python ] || python3 -m venv venv
venv/bin/python -m pip install --upgrade -r requirements.txt
(cd core/sidecar && npm install)

echo
echo "Done. Start the node with:  venv/bin/python main.py"
