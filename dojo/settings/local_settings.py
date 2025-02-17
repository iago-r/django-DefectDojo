from django.apps import apps
from django.urls import include, re_path

INSTALLED_APPS += ("polls_plugin",)

DATABASES["polls"] = {
    "ENGINE": "django.db.backends.sqlite3",
    "NAME": "/app/crivo-metadata/findings_polls.db",
}

DATABASE_ROUTERS = ["polls_plugin.router.PollsRouter"]


def get_extra_urlpatterns():
    if apps.ready:
        return [re_path(r"^finding(?:/open)?/", include("polls_plugin.urls"))]
    return []


EXTRA_URL_PATTERNS = get_extra_urlpatterns()

try:
    MIGRATION_MODULES.update({"polls_plugin": "polls_plugin.migrations"})
except NameError:
    print("Error: MIGRATION_MODULES is not defined. Make sure it is defined before updating it.")
