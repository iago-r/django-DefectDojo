#!/usr/bin/env python3
import csv
import gzip
import json
import logging
import pickle
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

# ruff: noqa: S314

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

WORKDIR = Path("/app/crivo-metadata/cve-metadata")


def process_epss_csv(basedir: Path, cve2meta: defaultdict[str, dict]):
    fp = basedir / "epss.csv.gz"
    if not fp.exists():
        logger.error("EPSS file not found (%s)", fp)
        msg = "EPSS file missing"
        raise ValueError(msg)
    logger.info("Loading EPSS data from %s", fp)
    with gzip.open(fp, "rt") as fd:
        _meta = fd.readline()
        reader = csv.DictReader(fd)
        # todo: skip lines of current header
        if reader.fieldnames != ["cve", "epss", "percentile"]:
            logger.error("EPSS CVS file format changed, aborting")
            msg = "EPSS file format changed"
            raise ValueError(msg)
        for row in reader:
            cve2meta[row["cve"].lower()]["epss"] = {
                "epss_score": float(row["epss"]),
                "epss_percentile": float(row["percentile"]),
            }


def process_kev_db(basedir: Path, cve2meta: dict[str, dict]):
    fp = basedir / "kev.json"
    if not fp.exists():
        logger.error("KEV file not found (%s)", fp)
        msg = "KEV file missing"
        raise ValueError(msg)
    logger.info("Loading KVE database from %s", fp)
    with open(fp, encoding="utf8") as fd:
        kevdb = json.load(fd)
        for vuln in kevdb["vulnerabilities"]:
            cve = vuln.pop("cveID").lower()
            cve2meta[cve]["kev"] = {
                "dateAdded": vuln["dateAdded"],
                "knownRansomwareCampaignUse": vuln["knownRansomwareCampaignUse"],
            }


def merge_cve_classification(basedir: Path, cve2meta: dict[str, dict]):
    fp = basedir / "classification.pkl.gz"
    if not fp.exists():
        logger.warning("CVE classification file not found (%s)", fp)
        msg = "CVE classification file missing"
        raise ValueError(msg)
    logger.info("Loading CVE classification data from %s", fp)
    with gzip.open(fp, "rb") as fd:
        cve2classification = pickle.load(fd)
    for cve, classification in cve2classification.items():
        cve2meta[cve.lower()]["classification"] = dict(classification[1])


def get_cwes(cvedata: dict, cwe2name: dict[str, str]) -> list[tuple[str, str]]:
    cwes: list[tuple[str, str]] = []
    try:
        problemtype_data = cvedata["cve"]["problemtype"]["problemtype_data"]
        for entry in problemtype_data:
            for description in entry["description"]:
                if description["value"].startswith("CWE"):
                    cweid = description["value"].lower()
                    cwes.append((cweid, cwe2name[cweid]))
    except KeyError:
        return []
    return cwes


def get_cpes(cvedata: dict) -> list[str]:
    cpes: list[str] = []
    try:
        nodes = cvedata["configurations"]["nodes"]
        for node in nodes:
            for cpe in node["cpe_match"]:
                if (cpe23 := cpe.get("cpe23Uri")) is not None:
                    cpes.append(cpe23)
    except KeyError:
        return []
    return cpes


def process_cve_files(basedir: Path, cwe2name: dict[str, str], cve2meta: dict[str, dict]):
    for fn in basedir.glob("nvdcve-1.1-*.json.gz"):
        logger.info("Loading CVE data from %s", fn)
        with gzip.open(fn, "r") as fd:
            data = json.load(fd)
        for cvedata in data["CVE_Items"]:
            cveid = cvedata["cve"]["CVE_data_meta"]["ID"].lower()
            if "baseMetricV2" in cvedata["impact"]:
                cve2meta[cveid]["impact"] = {
                    "cvss_score": float(cvedata["impact"]["baseMetricV2"].get("cvssV2", {}).get("baseScore")),
                    "cvss_vector": cvedata["impact"]["baseMetricV2"].get("cvssV2", {}).get("vectorString"),
                    "cvss_version": 2,
                }
            if "baseMetricV3" in cvedata["impact"]:
                cve2meta[cveid]["impact"] = {
                    "cvss_score": float(cvedata["impact"]["baseMetricV3"].get("cvssV3", {}).get("baseScore")),
                    "cvss_vector": cvedata["impact"]["baseMetricV3"].get("cvssV3", {}).get("vectorString"),
                    "cvss_version": 3,
                }

            cve2meta[cveid]["cwes"] = get_cwes(cvedata, cwe2name)
            cve2meta[cveid]["cpes"] = get_cpes(cvedata)


def process_cwe_db(basedir: Path) -> dict[str, str]:
    cwe2name = {}
    for fn in basedir.glob("cwe/*.xml"):
        logger.info("Loading CWE data from %s", fn)
        with open(fn, encoding="utf8") as fd:
            tree = ET.parse(fd)

        root = tree.getroot()
        ns = {"cwe": "http://cwe.mitre.org/cwe-7"}
        for weakness in root.findall(".//cwe:Weaknesses/cwe:Weakness", ns):
            cwe_id = f"cwe-{int(weakness.get('ID', 0))}"
            cwe_name = weakness.get("Name")
            if cwe_id and cwe_name:
                cwe2name[cwe_id] = cwe_name
    return cwe2name


# cve2meta[cveid]["epss"]: dict[str, float] = {epss_score: value, epss_percentile: value}
# cve2meta[cveid]["kev"]: dict = {dateAdded: "%Y-%m-%d", knownRansomwareCampaignUse: str}
# cve2meta[cveid]["cve"]: dict = {impact: cvss_dict, cwes: list[(cwe, name)], cpes: list[str]}
# cve2meta[cveid]["classification"]: dict[str, float] = {classname: probability}

# example cvss_dicts:
#      "impact": {
#        "baseMetricV2": {
#          "cvssV2": {
#            "version": "2.0",
#            "vectorString": "AV:L/AC:M/Au:N/C:C/I:C/A:C",
#            "accessVector": "LOCAL",
#            "accessComplexity": "MEDIUM",
#            "authentication": "NONE",
#            "confidentialityImpact": "COMPLETE",
#            "integrityImpact": "COMPLETE",
#            "availabilityImpact": "COMPLETE",
#            "baseScore": 6.9
#          },
#          "severity": "MEDIUM",
#          "exploitabilityScore": 3.4,
#          "impactScore": 10,
#          "obtainAllPrivilege": true,
#          "obtainUserPrivilege": false,
#          "obtainOtherPrivilege": false,
#          "userInteractionRequired": false
#        }
#      }
#
#      "impact": {
#        "baseMetricV3": {
#          "cvssV3": {
#            "version": "3.1",
#            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
#            "attackVector": "NETWORK",
#            "attackComplexity": "LOW",
#            "privilegesRequired": "NONE",
#            "userInteraction": "NONE",
#            "scope": "UNCHANGED",
#            "confidentialityImpact": "HIGH",
#            "integrityImpact": "HIGH",
#            "availabilityImpact": "HIGH",
#            "baseScore": 9.8,
#            "baseSeverity": "CRITICAL"
#          },
#          "exploitabilityScore": 3.9,
#          "impactScore": 5.9
#        }
#      }


def main():
    cve2meta = defaultdict(dict)
    process_epss_csv(WORKDIR, cve2meta)
    process_kev_db(WORKDIR, cve2meta)
    cwe2name = process_cwe_db(WORKDIR)
    process_cve_files(WORKDIR, cwe2name, cve2meta)
    merge_cve_classification(WORKDIR, cve2meta)
    cve2meta = dict(cve2meta)  # remove defaultdict before pickle
    with gzip.open(WORKDIR / "cve2meta.pkl.gz", "w") as fd:
        pickle.dump(cve2meta, fd)
    with open(WORKDIR / "cve2meta.json", "w", encoding="utf8") as fd:
        json.dump(cve2meta, fd)


if __name__ == "__main__":
    main()
