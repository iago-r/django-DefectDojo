#!/bin/sh
set -eu

# create directories in CRIVO_STORAGE_PATH if not exist
mkdir -p "$CRIVO_STORAGE_PATH/model"
mkdir -p "$CRIVO_STORAGE_PATH/model/user_votes"
mkdir -p "$CRIVO_STORAGE_PATH/model/predict_votes"
chmod -R 777 "$CRIVO_STORAGE_PATH/model"

echo "Waiting changes in $CRIVO_STORAGE_PATH..."
while true; do
  EVENT=$(inotifywait -e modify,create -r --format '%w%f' "$CRIVO_STORAGE_PATH/model/user_votes")
  echo "Change detected at $(date '+%Y-%m-%d %H:%M:%S') in $EVENT"
  python3 /usr/src/app/model/update_model.py "$EVENT"
done