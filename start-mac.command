#!/bin/bash
# Double-click on macOS to start ThreatPulse (first time: right-click > Open).
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is not installed. Install it from https://www.python.org/downloads/ and run this again."
  open "https://www.python.org/downloads/"
  read -r -p "Press Enter to close..."
  exit 1
fi
echo "Starting ThreatPulse... your browser will open automatically."
python3 run.py --open "$@"
