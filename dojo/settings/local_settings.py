from django.apps import apps
from django.urls import include, re_path


CELERY_BEAT_SCHEDULE.update({
    "daily-cache-update": {
        "task": "dojo.problem.update_mappings.daily_cache_update",
        "schedule": crontab(minute=0, hour=0),  # every day at midnight
    }
})

CELERY_IMPORTS += ("dojo.problem.update_mappings",)

# By default, this mapping is not configured (set to None). If configured, it allows
# the "Problems" button to appear in Dojo's left toolbar.
# You can check more information in https://pugna.snes.dcc.ufmg.br/defectdojo/README.md
# A finding-to-problem mapping covering Nmap, OpenVAS and Nuclei is available in
# <https://pugna.snes.dcc.ufmg.br/defectdojo/disambiguator.json>
PROBLEM_MAPPINGS_JSON_URL = "https://pugna.snes.dcc.ufmg.br/defectdojo/disambiguator.json"

INSTALLED_APPS += ("polls_plugin",)

DATABASES["polls"] = {
    "ENGINE": "django.db.backends.sqlite3",
    "NAME": "/app/crivo-metadata/findings_polls.db",
}

DATABASE_ROUTERS = ["polls_plugin.router.PollsRouter"]

try:
    MIGRATION_MODULES.update({"polls_plugin": "polls_plugin.migrations"})
except NameError:
    print("Error: MIGRATION_MODULES is not defined. Make sure it is defined before updating it.")
