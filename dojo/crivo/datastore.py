import gzip
import logging
import pathlib
import pickle
import re
import threading

from django.conf import settings

logger = logging.getLogger(__name__)


class DataStore:
    _instance = None
    _lock = threading.Lock()
    _is_loaded = False
    FINDING_DESCRIPTION_GET_CVES = re.compile(r"\*\*CVEs\*\*: (.+)")
    CVE_CLASSIFICATION_THRESHOLD = settings.CVE_CLASSIFICATION_THRESHOLD

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.data = {}
        return cls._instance

    def load(self, metadata_fp="/app/crivo-metadata/cve-metadata/cve2meta.pkl.gz"):
        if not pathlib.Path(metadata_fp).exists():
            logger.warning("CRIVO DataStore metadata file missing (%s)", metadata_fp)
            return

        with gzip.open(metadata_fp, "rb") as fd:
            self.data = pickle.load(fd)

        self._is_loaded = True

    def get_data(self):
        return self.data

    def parse_desc(self, description):
        match = self.FINDING_DESCRIPTION_GET_CVES.search(description)
        if not match:
            logger.warning("No CVEs found in description")
            return []
        return [cve.strip() for cve in match.group(1).split(",")]

    def get_metadata(self, description):
        cves = self.parse_desc(description)
        if not cves:
            return {}

        cves_metadata = []
        all_keys = {"epss_score", "epss_percentile", "cvss_label", "cvss_score", "in_kev", "cve_classes", "cwes", "cpes"}
        for cve in cves:
            # check if cve is in the data and get metadata for cve
            if (metadata := self.data.get(cve.lower(), None)) is None:
                logger.warning("No metadata found for CVE: %s", cve)
                continue

            cve_metadata = dict.fromkeys(all_keys, None)

            if (epss := metadata.get("epss")) is not None:
                cve_metadata["epss_score"] = round(epss.get("epss_score"), 2)
                cve_metadata["epss_percentile"] = round(epss.get("epss_percentile"), 2)

            if (impact := metadata.get("impact")) is not None:
                cve_metadata["cvss_label"] = f"CVSSv{impact.get('cvss_version')}"
                cve_metadata["cvss_score"] = impact.get("cvss_score")

            cve_metadata["in_kev"] = "kev" in metadata

            if (class_distribution := metadata.get("classification")) is not None:
                cve_metadata["cve_classes"] = [
                    k.title() for k, v in class_distribution.items() if v > self.CVE_CLASSIFICATION_THRESHOLD]

            cve_metadata["cwes"] = metadata.get("cwes", [])
            cve_metadata["cpes"] = metadata.get("cpes", [])

            cves_metadata.append({"cve_id": cve, "cve_metadata": cve_metadata})

        def cve_sort_key(cve):
            in_kev = cve["cve_metadata"]["in_kev"]
            epss_score = cve["cve_metadata"]["epss_score"]
            cvss_score = cve["cve_metadata"]["cvss_score"]
            return (in_kev, epss_score, cvss_score)

        return sorted(cves_metadata, key=cve_sort_key, reverse=True)
