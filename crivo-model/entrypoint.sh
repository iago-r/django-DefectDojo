#!/bin/sh
set -eu

echo "Waiting changes in $CRIVO_STORAGE_PATH..."
while true; do
  EVENT=$(inotifywait -e modify,create -r --format '%w%f' "$CRIVO_STORAGE_PATH/user_votes")
  echo "Change detected at $(date '+%Y-%m-%d %H:%M:%S') in $EVENT"
  python3 /usr/src/app/update_model.py "$EVENT"
done