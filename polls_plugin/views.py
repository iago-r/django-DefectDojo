import json
import logging
import os
import pickle
from pathlib import Path

from django.contrib.auth.decorators import login_required
from django.db.models import Max
from django.http import JsonResponse
from django.utils.timezone import now
from django.views.decorators.http import require_GET

from dojo.models import Finding

from .models import Vote

logger = logging.getLogger(__name__)

WORKDIR = Path(os.getenv("CRIVO_STORAGE_PATH"))
VOTES_WORKDIR = WORKDIR / "model/user_votes"

if not VOTES_WORKDIR.exists():
    VOTES_WORKDIR.mkdir(parents=True)


@login_required
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


@require_GET
@login_required
def update_risks(request):
    latest_votes = Vote.objects.filter(is_model_inference=False, user_id=request.user.id).values("finding_id", "user_id").annotate(
        latest_timestamp=Max("timestamp"),
    )
    votes_data = []
    for vote in latest_votes:
        detailed_vote = Vote.objects.filter(
            finding_id=vote["finding_id"],
            user_id=vote["user_id"],
            timestamp=vote["latest_timestamp"],
            is_model_inference=False,
        ).first()

        if detailed_vote:
            votes_data.append(
                {
                    "id": detailed_vote.finding_id,
                    "user_id": detailed_vote.user_id,
                    "vote_class": detailed_vote.vote_class,
                    "timestamp": detailed_vote.timestamp.isoformat(),
                },
            )
    if not votes_data:
        return JsonResponse({"message": "No votes found. Not updating model."})
    findings_data = []
    for finding in Finding.objects.all():
        findings_data.append(
            {
                "id": finding.id,
                "title": finding.title,
                "date": finding.date,
                "description": finding.description,
                "severity": finding.severity,
                "vuln_id_from_tool": finding.vuln_id_from_tool,
                "mitigation": finding.mitigation,
                "epss_score": finding.epss_score,
                "epss_percentile": finding.epss_percentile,
                "cve": finding.cve,
            },
        )
    if not findings_data:
        return JsonResponse({"message": "No findings available. Not updating model."})

    features_file_path = WORKDIR / "model/finding_features.pkl"
    with open(features_file_path, "wb") as f:
        pickle.dump(findings_data, f)

    vote_file_path = VOTES_WORKDIR / f"{request.user.id}_votes.pkl"
    with open(vote_file_path, "wb") as f:
        pickle.dump(votes_data, f)

    return JsonResponse({"message": "Retraining Model"})
