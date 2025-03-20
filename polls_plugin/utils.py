import logging

from django.db import OperationalError
from django.db.models import OuterRef, Subquery

logger = logging.getLogger(__name__)

from .models import Vote


def get_user_votes(user_id):
    try:
        if not Vote.objects.exists():
            logger.info("No records found in table 'Vote'.")
            return {}

        latest_votes_subquery = (
            Vote.objects.filter(user_id=user_id, finding_id=OuterRef("finding_id"))
            .order_by("-timestamp")
            .values("timestamp")[:1]
        )

        latest_votes = Vote.objects.filter(user_id=user_id, timestamp=Subquery(latest_votes_subquery)).values(
            "finding_id",
            "vote_class",
        )

        return {str(v["finding_id"]): v["vote_class"] for v in latest_votes}

    except OperationalError as e:
        logger.info("Error accessing database: " + str(e))
        return {}
