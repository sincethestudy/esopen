#!/bin/bash
# esopen launcher: downloads the latest esopen.py to ~/.esopen and runs it.
#
#   curl -fsSL https://raw.githubusercontent.com/sincethestudy/esopen/main/run.sh | bash
#
# Pass options after `bash -s --`, for example fake data with no password:
#
#   curl -fsSL https://raw.githubusercontent.com/sincethestudy/esopen/main/run.sh | bash -s -- --demo
set -euo pipefail

URL="https://raw.githubusercontent.com/sincethestudy/esopen/main/esopen.py"
DIR="$HOME/.esopen"

if [ "$(uname)" != "Darwin" ]; then
  echo "esopen only runs on macOS." >&2
  exit 1
fi
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
  echo "esopen needs Python 3.9 or newer, which comes with Apple's Command Line Tools." >&2
  echo "If macOS just offered to install them, click Install, wait for it to finish, then run this again." >&2
  echo "Otherwise run:  xcode-select --install" >&2
  exit 1
fi

mkdir -p "$DIR"
echo "Downloading esopen..."
curl -fsSL "$URL" -o "$DIR/esopen.py.download"
mv "$DIR/esopen.py.download" "$DIR/esopen.py"
echo "Saved to ~/.esopen/esopen.py (next time you can run: python3 ~/.esopen/esopen.py)"

# When piped into bash, stdin is the script itself; hand the terminal back to esopen for the password prompt.
if { : < /dev/tty; } 2>/dev/null; then
  exec python3 "$DIR/esopen.py" "$@" < /dev/tty
fi
exec python3 "$DIR/esopen.py" "$@"
