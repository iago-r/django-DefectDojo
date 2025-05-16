from django.urls import re_path

from .views import save_user_vote, update_risks

urlpatterns = [
    re_path(r"^save_vote/$", save_user_vote, name="save_user_vote"),
    re_path(r"^update_risks/$", update_risks, name="update_risks"),
]
