#!/bin/sh
set -eu

# create directories in CRIVO_STORAGE_PATH if not exist
mkdir -p "$CRIVO_STORAGE_PATH/model/user_votes"
mkdir -p "$CRIVO_STORAGE_PATH/model/finding_features"
mkdir -p "$CRIVO_STORAGE_PATH/model/predict_votes"

# Permissions: 
# 755 - owner can read/write/execute, others can read/execute
# 777 - needed to remove files created by the model and to allow the model to write to these directories
chmod 755 "$CRIVO_STORAGE_PATH/model"
chmod 777 "$CRIVO_STORAGE_PATH/model/predict_votes"
chmod 777 "$CRIVO_STORAGE_PATH/model/user_votes"
chmod 777 "$CRIVO_STORAGE_PATH/model/finding_features"

python3 /usr/src/app/model/update_model.py