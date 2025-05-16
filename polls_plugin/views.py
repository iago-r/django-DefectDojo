import json
import logging
import os
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
VOTES_WORKDIR = WORKDIR / "user_votes"

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
    finding_info = {}
    latest_votes = Vote.objects.filter(is_model_inference=False, user_id=request.user.id).values("finding_id", "user_id").annotate(
        latest_timestamp=Max("timestamp"),
    )
    for vote in latest_votes:
        detailed_vote = Vote.objects.filter(
            finding_id=vote["finding_id"],
            user_id=vote["user_id"],
            timestamp=vote["latest_timestamp"],
            is_model_inference=False,
        ).first()
        logger.info(f"Detailed vote: {detailed_vote}")

        if detailed_vote and detailed_vote.vote_class:
            finding_info[detailed_vote.finding_id] = {
                "vote": detailed_vote.vote_class,
            }
    for finding_id in finding_info:
        finding = Finding.objects.filter(id=finding_id).first()
        if finding:
            finding_info[finding_id]["features"] = {
                "title": finding.title,
                "date": finding.date.isoformat() if finding.date else None,
                "description": finding.description,
                "severity": finding.severity,
                "vuln_id_from_tool": finding.vuln_id_from_tool,
                "mitigation": finding.mitigation,
                "epss_score": finding.epss_score,
                "epss_percentile": finding.epss_percentile,
                "cve": finding.cve,
            }
        else:
            finding_info.pop(finding_id, None)
    if not finding_info:
        logger.info("No votes found. Not updating model.")
        return JsonResponse({"message": "No votes found. Not updating model."})
    user_votes_info = {
        "user_id": request.user.id,
        "user_findings": finding_info,
    }

    vote_file_path = VOTES_WORKDIR / f"{request.user.id}_votes_info.json"
    with vote_file_path.open("w", encoding="utf-8") as f:
        json.dump(user_votes_info, f)

    return JsonResponse({"message": "Risks updated successfully"})
