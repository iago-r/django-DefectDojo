#!/bin/sh
set -eux

STORAGE=/app/crivo-metadata

chmod 777 $STORAGE

curl --silent --output $STORAGE/disambiguator.json \
        https://pugna.snes.dcc.ufmg.br/defectdojo/disambiguator.json

mkdir -p $STORAGE/cve-metadata
chmod 777 $STORAGE/cve-metadata

curl --silent --output $STORAGE/cve-metadata/classification.pkl.gz \
        https://pugna.snes.dcc.ufmg.br/defectdojo/cve-classification.pkl.gz

curl --location --silent --output $STORAGE/cve-metadata/epss.csv.gz \
        https://epss.empiricalsecurity.com/epss_scores-current.csv.gz

curl --location --silent --output $STORAGE/cve-metadata/kev.csv \
        https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv

gunzip --force $STORAGE/cve-metadata/classification.pkl.gz
gunzip --force $STORAGE/cve-metadata/epss.csv.gz

for year in $(seq 2002 2025) ; do
    curl --silent --output $STORAGE/cve-metadata/nvdcve-1.1-$year.json.gz \
            https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$year.json.gz
    gunzip --force $STORAGE/cve-metadata/nvdcve-1.1-$year.json.gz
done

ls -al $STORAGE
ls -al $STORAGE/cve-metadata
