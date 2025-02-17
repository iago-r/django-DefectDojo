from django.db.models import Max

from .models import Vote


def get_user_votes(user_id):
    votes = (
        Vote.objects.filter(user_id=user_id)
        .values("finding_id")
        .annotate(latest_timestamp=Max("timestamp"))
        .order_by("finding_id", "-latest_timestamp")
    )

    latest_votes = Vote.objects.filter(
        user_id=user_id,
        timestamp__in=[v["latest_timestamp"] for v in votes],
    ).values("finding_id", "vote_class")

    return {str(v["finding_id"]): v["vote_class"] for v in latest_votes}
