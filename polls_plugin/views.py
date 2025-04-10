import json
import logging

from django.contrib.auth.decorators import login_required
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
        result_id = data.get("result_id")
        vote_value = data.get("vote")
        vote_type = data.get("vote_type")

        if vote_type == "class" and vote_value not in [choice[0] for choice in Vote.VOTE_CHOICES_CLASS]:
            logger.error("Invalid vote value for class.")
            return JsonResponse({"error": "Invalid Vote"}, status=400)
        if vote_type == "num" and vote_value not in [choice[0] for choice in Vote.VOTE_CHOICES_NUM]:
            logger.error("Invalid vote value for num.")
            return JsonResponse({"error": "Invalid Vote"}, status=400)

        vote_kwargs = {
            "user_id": request.user.id,
            "finding_id": finding_id,
            "result_id": result_id,
            "timestamp": now(),
        }

        if vote_type == "class":
            vote_kwargs["vote_class"] = vote_value
        elif vote_type == "num":
            vote_kwargs["vote_num"] = vote_value

        Vote.objects.create(**vote_kwargs)

        return JsonResponse({"message": "Vote Saved"})

    except (ValueError, TypeError, json.JSONDecodeError) as e:
        logger.error(f"Error while processing the vote: {e}")
        return JsonResponse({"error": "Invalid Data"}, status=400)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return JsonResponse({"error": "An unexpected error occurred"}, status=500)
