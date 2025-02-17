import gzip
import logging
import pathlib
import pickle
import threading

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

    def load(self, metadata_fp="/app/crivo-metadata/cve-metadata/cve2meta.pkl.gz"):
        if not pathlib.Path(metadata_fp).exists():
            logger.warning("CRIVO DataStore metadata file missing (%s)", metadata_fp)
            return

        with gzip.open(metadata_fp, "rb") as fd:
            self.data = pickle.load(fd)

        self._is_loaded = True

    def get_data(self):
        return self.data
