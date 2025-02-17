import json
import logging

from django.contrib.auth.decorators import login_required
from django.db.models import Max
from django.http import JsonResponse
from django.utils.timezone import now
from django.views.decorators.csrf import csrf_exempt

from .models import Vote

logger = logging.getLogger(__name__)


@login_required
@csrf_exempt
def save_user_vote(request):
    logger.debug("Received a request.")

    if request.method != "POST":
        logger.error("Invalid request method.")
        return JsonResponse({"error": "Method Not Allowed"}, status=405)

    try:
        data = json.loads(request.body)
        logger.debug(f"Request body data: {data}")

        finding_id = int(data.get("finding_id"))
        vote_value = data.get("vote")

        if vote_value not in [choice[0] for choice in Vote.VOTE_CHOICES_CLASS]:
            logger.error("Invalid vote value.")
            return JsonResponse({"error": "Invalid Vote"}, status=400)

        Vote.objects.create(
            user_id=request.user.id,
            finding_id=finding_id,
            vote_class=vote_value,
            timestamp=now(),
        )

        return JsonResponse({"message": "Vote Saved"})

    except (ValueError, TypeError, json.JSONDecodeError) as e:
        logger.error(f"Error while processing the vote: {e}")
        return JsonResponse({"error": "Invalid Data"}, status=400)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return JsonResponse({"error": "An unexpected error occurred"}, status=500)
