import threading
import logging
import os
import csv
import json
import pickle

logger = logging.getLogger(__name__)

class DataStore:
    _instance = None
    _lock = threading.Lock()
    _is_loaded = False
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.data = {}
        return cls._instance
        
        
    def load_file(self, file_path):
        "import file to data store"
        
        filename, extension = os.path.splitext(os.path.basename(file_path))
        
        data = {}
        logger.info(f"Reading {os.path.basename(file_path)}")
        if extension == ".json":
            with open(file_path, "r") as file:
                data_raw = json.load((file))
                for i in data_raw["CVE_Items"]:
                    cve_id = i["cve"]["CVE_data_meta"]["ID"]
                    if cve_id not in data:
                        data[cve_id] = {}
                    data[cve_id]["impact"] = i["impact"]
                    
        elif extension == ".csv":

            with open(file_path, "r") as file:
                data_reader = csv.reader(file)
                next(data_reader) # skips the column names
                for row in data_reader:
                    cve_id = row[0]
                    if cve_id not in data:
                        data[cve_id] = {}
                    if filename == "epss":
                        data[cve_id]["epss"] = {}
                        data[cve_id]["epss"]["epss_score"] = row[1]
                        data[cve_id]["epss"]["epss_percentile"] = row[2]
                    elif filename == "kev":
                        data[cve_id]["kev"] = row
                    else:
                        raise Exception ("CSV content not identified")
        elif extension == ".pkl":
            with open(file_path, "rb") as file:
                data_raw = pickle.load(file)
                for cve_id, value in data_raw.items():
                    if cve_id not in data:
                        data[cve_id] = {}
                    data[cve_id]["classification"] = {}
                    data[cve_id]["classification"]["class_prob_dist"] = value[1]
                    data[cve_id]["classification"]["description"] = value[0]
                    

        else:
            raise Exception(
                "Unsuported file type: file type should be either .json, .csv or .pkl"
            )
        return data
    
    def load_all_files(self, dir="/app/cve-data/"):
        import os
        
        files = sorted([
            os.path.join(dir, f)
            for f in os.listdir(dir)
            if os.path.isfile(os.path.join(dir, f))
        ])

        results = []
        for i in files:
            results.append(self.load_file(i))
            
            # results are a list of dictionaries for each file

        self.data = self.merge_dictionaries(results)
        
        
        self._is_loaded = True
    
    
    def merge_dictionaries(self, dicts):
        merged = {}
        
        for dictionary in dicts:
          for key, value in dictionary.items():
            if key not in merged:
              merged[key] = value
            elif isinstance(value, dict) and isinstance(merged[key], dict):
              merged[key] = self.merge_dictionaries([merged[key], value])
            else:
              merged[key] = value
         
        return merged
        
        # for d in dicts:
        #     for key,value in d.items():
        #         if isinstance(value, dict):
        #             merged[key] = self.merge_dictionaries([merged.get(key, {}), value])
        #         else:
        #             merged[key] = value if merged.get(key) is None else merged[key]
        
        # return merged
    
    def get_data(self):
        return self.data