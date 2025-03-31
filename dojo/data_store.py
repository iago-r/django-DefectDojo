import csv
import json
import logging
import pickle
import threading
from pathlib import Path

from django.conf import settings

logger = logging.getLogger(__name__)

# This class is a singleton that loads and stores metadata from various files
# and provides methods to access the data.
# It uses a thread to load the files in the background, ensuring that the
# application can continue running without blocking.
# The data is stored in a dictionary, and the class provides methods to
# load files, parse data, and merge dictionaries.
# It also provides a method to get the loaded data.
# The class is designed to be thread-safe, ensuring that multiple threads
# can access the data at the same time.


class DataStore:
    _instance = None
    _lock = threading.Lock()
    _is_loaded = False
    CLASSIFICATION_THRESHOLD = settings.CLASSIFICATION_THRESHOLD

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.data = {}
        return cls._instance

    def load_all_files(self, directory=settings.CVE_METADATA_DIR):
        """
        Load all CVE metadata files from the specified directory.

        Keyword Arguments:
        directory -- The directory containing the CVE metadata files

        Return: None: updates the data attribute with the loaded data

        """
        pickle_path = Path(settings.CVE_METADATA_PICKLE)
        if pickle_path.exists():
            try:
                logger.info(f"Loading data from existing pickle: {settings.CVE_METADATA_PICKLE}")
                with open(pickle_path, "rb") as file:
                    self.data = pickle.load(file)
                self._is_loaded = True
                logger.info("Data loaded successfully from pickle")
            except Exception as e:
                logger.warning(f"Failed to load pickle file: {e}. Will reload from source files.")

        else:
            logger.info(f"Pickle file not found: {settings.CVE_METADATA_PICKLE}. Loading from source files.")
            if not Path(directory).exists():
                logger.error(f"Directory {directory} does not exist")
                return
            files = sorted([f for f in Path(directory).iterdir() if f.is_file()])

            results = []
            for file in files:
                file_dict = self.load_file(file)
                if file_dict:
                    results.append(file_dict)

            if not results:
                logger.error(f"No files found in {directory}")
                return
            if len(results) == 1:
                self.data = results[0]
            else:
                # Merge all dictionaries into one
                logger.info("Merging dictionaries")
                self.data = self.merge_dictionaries(results)

            logger.info("Data loaded successfully")
            self._is_loaded = True

            with open(settings.CVE_METADATA_PICKLE, "wb") as file:
                pickle.dump(self.data, file)

            logger.info(f"Data saved to {settings.CVE_METADATA_PICKLE}")

    def load_file(self, file_path):
        filename = Path(file_path).name
        data = {}
        logger.info(f"Reading {filename}")

        all_keys = ["epss_score", "epss_percentile", "kev", "cvss2", "cvss3", "classification"]

        if "nvdcve" in filename.lower() and filename.lower().endswith(".json"):
            self.parse_cvss_data(file_path, filename, data, all_keys)

        elif "epss" in filename.lower() and filename.lower().endswith(".csv"):
            self.parse_epss_data(file_path, filename, data, all_keys)

        elif "kev" in filename.lower() and filename.lower().endswith(".csv"):
            self.parse_kev_data(file_path, filename, data, all_keys)

        elif "classification" in filename.lower() and filename.lower().endswith(".pkl"):
            self.parse_classification_data(file_path, filename, data, all_keys)

        else:
            logger.error(f"Failed to load {filename}: Unsupported file format")

        return data

    def parse_cvss_data(self, file_path, filename, data, all_keys):
        try:
            with open(file_path, encoding="utf-8") as file:
                data_raw = json.load(file)
                if "CVE_Items" in data_raw:
                    for cve in data_raw["CVE_Items"]:
                        cve_meta = cve.get("cve", {}).get("CVE_data_meta", {})
                        cve_id = cve_meta.get("ID")

                        if not cve_id:
                            continue

                        if cve_id not in data:
                            data[cve_id] = dict.fromkeys(all_keys, None)

                        impact = cve.get("impact", {})
                        cvss2 = impact.get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore")
                        cvss3 = impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore")

                        if cvss2 is not None:
                            data[cve_id]["cvss2"] = cvss2
                        if cvss3 is not None:
                            data[cve_id]["cvss3"] = cvss3
        except json.JSONDecodeError:
            logger.error(f"Failed to parse JSON file: {filename}")
        except OSError:
            logger.error(f"IO Error: Failed to load {filename}")

    def parse_epss_data(self, file_path, filename, data, all_keys):
        try:
            with open(file_path, encoding="utf-8") as file:
                data_reader = csv.DictReader(file)
                if data_reader.fieldnames != ["cve", "epss", "percentile"]:
                    logger.error(f"Invalid CSV column header: {data_reader.fieldnames}")
                    return
                for dict_row in data_reader:
                    cve_id = dict_row.get("cve", None)
                    if cve_id is None:
                        continue

                    if cve_id not in data:
                        data[cve_id] = dict.fromkeys(all_keys, None)

                    data[cve_id]["epss_score"] = dict_row.get("epss", None)
                    data[cve_id]["epss_percentile"] = dict_row.get("percentile", None)
        except csv.Error:
            logger.error(f"Failed to parse EPSS CSV file: {filename}")
        except OSError:
            logger.error(f"IO Error: Failed to load {filename}")

    def parse_kev_data(self, file_path, filename, data, all_keys):
        try:
            with open(file_path, encoding="utf-8") as file:
                data_reader = csv.DictReader(file)
                for dict_row in data_reader:
                    cve_id = dict_row.get("cveID", None)
                    if cve_id is None:
                        continue

                    if cve_id not in data:
                        data[cve_id] = dict.fromkeys(all_keys, None)

                    data[cve_id]["kev"] = True
        except csv.Error:
            logger.error(f"Failed to parse KEV CSV file: {filename}")
        except OSError:
            logger.error(f"IO Error: Failed to load {filename}")

    def parse_classification_data(self, file_path, filename, data, all_keys):
        try:
            with open(file_path, "rb") as file:
                data_raw = pickle.load(file)
                for cve_id in data_raw:
                    if cve_id not in data:
                        data[cve_id] = dict.fromkeys(all_keys, None)
                    data[cve_id]["classification"] = []
                    if isinstance(data_raw[cve_id], tuple) and len(data_raw[cve_id]) == 2:
                        for cls in data_raw[cve_id][1]:
                            if data_raw[cve_id][1][cls] > self.CLASSIFICATION_THRESHOLD:
                                data[cve_id]["classification"].append(cls)
        except (pickle.UnpicklingError, EOFError):
            logger.error(f"Failed to load {filename}: Unsupported file format")
        except OSError:
            logger.error(f"IO Error: Failed to load {filename}")

    def merge_dictionaries(self, dict_list):
        result = {}

        for dictionary in dict_list:
            for cve_id, cve_metadata in dictionary.items():
                if cve_id not in result:
                    result[cve_id] = cve_metadata

                else:
                    for key, value in cve_metadata.items():
                        if key not in result[cve_id]:
                            result[cve_id][key] = value
                        elif value is not None:
                            # Only overwrite if the value is not None
                            result[cve_id][key] = value
        return result

    def get_data(self):
        return self.data
