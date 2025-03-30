CELERY_BEAT_SCHEDULE.update({
    "daily-cache-update": {
        "task": "dojo.problem.update_mappings.daily_cache_update",
        "schedule": crontab(minute=0, hour=0),  # every day at midnight
    }
})

CELERY_IMPORTS += ("dojo.problem.update_mappings",)

# To disable the Problems module inside Dojo, you can set `PROBLEM_MAPPINGS_JSON_URL` to `None`.
# You can check more information at https://pugna.snes.dcc.ufmg.br/defectdojo/README.md.
# This default setting assumes that the `crivo-init` container has already been run:
PROBLEM_MAPPINGS_JSON_URL = "file:///app/crivo-metadata/disambiguator.json"
# A finding-to-problem mapping covering Nmap, OpenVAS and Nuclei is available from UFMG:
# PROBLEM_MAPPINGS_JSON_URL = "https://pugna.snes.dcc.ufmg.br/defectdojo/disambiguator.json"


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
