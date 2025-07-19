#!/bin/bash
set -eu

echo "[+] Copying datastore.py from dojo"
cp ../dojo/crivo/datastore.py model/datastore.py

echo "[+] Building crivo-model"
docker compose -f ../docker-compose.yml -f ../docker-compose-crivo.yml build crivo-model

echo "[+] Removing datastore.py"
rm model/datastore.py

echo "[✔] Build complete."
echo "To run the container manually, execute:"
echo "docker compose -f ../docker-compose.yml -f ../docker-compose-crivo.yml up -d crivo-model"
