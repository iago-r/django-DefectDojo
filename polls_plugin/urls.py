from django.urls import re_path

from .views import save_user_vote

urlpatterns = [
    re_path(r"^save_vote/$", save_user_vote, name="save_user_vote"),
]
