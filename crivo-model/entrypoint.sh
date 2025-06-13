#!/bin/sh
set -eu

# create directories in CRIVO_STORAGE_PATH if not exist
mkdir -p "$CRIVO_STORAGE_PATH/model/user_votes"
mkdir -p "$CRIVO_STORAGE_PATH/model/predict_votes"

# Permissions: 
# 755 - owner can read/write/execute, others can read/execute
# 777 - needed only where Django writes (user_votes)
chmod 755 "$CRIVO_STORAGE_PATH/model"
chmod 755 "$CRIVO_STORAGE_PATH/model/predict_votes"
chmod 777 "$CRIVO_STORAGE_PATH/model/user_votes"

echo "Waiting changes in $CRIVO_STORAGE_PATH..."
while true; do
  EVENT=$(inotifywait -e modify,create -r --format '%w%f' "$CRIVO_STORAGE_PATH/model/user_votes")
  echo "Change detected at $(date '+%Y-%m-%d %H:%M:%S') in $EVENT"
  python3 /usr/src/app/model/update_model.py "$EVENT"
done