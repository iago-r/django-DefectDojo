import os

CRIVO_METADATA_DIR = os.getenv("CRIVO_STORAGE_PATH", "/app/crivo-metadata")

# Vulnerability Aggregation (Problems)
# ruff: noqa: F821, T201
CELERY_BEAT_SCHEDULE.update(
    {
        "daily-cache-update": {
            "task": "dojo.problem.update_mappings.daily_cache_update",
            "schedule": crontab(minute=0, hour=0),  # every day at midnight
        },
    },
)

CELERY_IMPORTS += ("dojo.problem.update_mappings",)

# To disable the Problems module inside Dojo, you can set `PROBLEM_MAPPINGS_JSON_URL` to `None`.
# You can check more information at https://pugna.snes.dcc.ufmg.br/defectdojo/README.md.
# This default setting assumes that the `crivo-init` container has already been run:
PROBLEM_MAPPINGS_JSON_URL = "file://{CRIVO_METADATA_DIR}/disambiguator.json"
# A finding-to-problem mapping covering Nmap, OpenVAS and Nuclei is available from UFMG:
# PROBLEM_MAPPINGS_JSON_URL = "https://pugna.snes.dcc.ufmg.br/defectdojo/disambiguator.json"

# Polls Plugin
INSTALLED_APPS += ("polls_plugin",)

DATABASES["polls"] = {
    "ENGINE": "django.db.backends.sqlite3",
    "NAME": f"{CRIVO_METADATA_DIR}/findings_polls.db",
}

DATABASE_ROUTERS = ["polls_plugin.router.PollsRouter"]

try:
    MIGRATION_MODULES.update({"polls_plugin": "polls_plugin.migrations"})
except NameError:
    print("Error: MIGRATION_MODULES is not defined. Make sure it is defined before updating it.")

# CVE Metadata
CVE_CLASSIFICATION_THRESHOLD = 0.4
CVE_METADATA_DIR = f"{CRIVO_METADATA_DIR}/cve-metadata"
CVE_METADATA_PICKLE = f"{CRIVO_METADATA_DIR}/cve-metadata.pkl"
