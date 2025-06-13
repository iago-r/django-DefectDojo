from django.db.models import Max, OuterRef, Subquery

from .models import Vote


def get_user_votes(user_id):
    latest_timestamp_subquery = Vote.objects.filter(
        user_id=user_id,
        finding_id=OuterRef("finding_id"),
        is_model_inference=False,
    ).values("finding_id").annotate(
        latest_timestamp=Max("timestamp"),
    ).values("latest_timestamp")

    latest_votes = Vote.objects.filter(
        user_id=user_id,
        is_model_inference=False,
        timestamp=Subquery(latest_timestamp_subquery),
    ).values("finding_id", "vote_class")

    return {str(v["finding_id"]): v["vote_class"] for v in latest_votes}


def get_model_inference_votes(user_id):
    latest_timestamp_subquery = Vote.objects.filter(
        user_id=user_id,
        finding_id=OuterRef("finding_id"),
        is_model_inference=True,
    ).values("finding_id").annotate(
        latest_timestamp=Max("timestamp"),
    ).values("latest_timestamp")

    latest_votes = Vote.objects.filter(
        user_id=user_id,
        is_model_inference=True,
        timestamp=Subquery(latest_timestamp_subquery),
    ).values("finding_id", "vote_class")

    return {str(v["finding_id"]): v["vote_class"] for v in latest_votes}
