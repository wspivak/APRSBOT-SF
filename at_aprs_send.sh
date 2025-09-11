#!/bin/bash

# === Configuration ===
WORKDIR="/opt/aprsbot"
PYTHON="/usr/bin/python3"
MODULE="ioreth.tatical_text_msg"
CALLSIGN="ERLI"
LOGFILE="/tmp/at_debug.log"

# === Input ===
MESSAGE="$1"
DELAY_MINUTES="${2:-1}"  # default to 1 minute if not provided

# === Validate ===
if [[ -z "$MESSAGE" ]]; then
  echo "Usage: $0 \"Your message\" [delay_minutes]"
  exit 1
fi

# === Time String for 'at' ===
TIME_STR="now + $DELAY_MINUTES minute"

# === Expanded command ===
CMD="cd $WORKDIR && echo '[AT] Running at: \$(date)' >> $LOGFILE && $PYTHON -m $MODULE $CALLSIGN \"$MESSAGE\" >> $LOGFILE 2>&1"

# === Schedule with 'at' ===
echo "$CMD" | at -M "$TIME_STR"
