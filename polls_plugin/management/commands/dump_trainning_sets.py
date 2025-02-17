import json
import logging
import pickle
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from dojo.models import Finding
from polls_plugin.models import Vote

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = """
    Extract votes or finding data and save them in JSON or Pickle.

    Usage:
      python manage.py dumpo_trainning_sets --data_type=<votes|features|both> --output_format=<json|pickle> [--filename=<filename>]

    Options:
      --data_type     Specify the type of data to extract: 'votes', 'features', or 'both'.
      --output_format Specify the output format: 'json' or 'pickle'.
      --filename      Specify the output file name (default: 'output_data').
    """

    def add_arguments(self, parser):
        parser.add_argument(
            "--data_type",
            type=str,
            choices=["votes", "features", "both"],
            help="Specify the type of data to extract: 'votes', 'features', or 'both'.",
        )
        parser.add_argument(
            "--output_format",
            type=str,
            choices=["json", "pickle"],
            help="Specify the output format: 'json' or 'pickle'.",
        )
        parser.add_argument(
            "--filename",
            type=str,
            default="output_data",
            help="Specify the output file name (without extension).",
        )

    def handle(self, *args, **options):
        if not options["data_type"] or not options["output_format"]:
            self.print_help("", "")
            return

        data_type = options["data_type"]
        output_format = options["output_format"]
        filename = options["filename"]

        data_to_save = {}

        if data_type in {"votes", "both"}:
            votes_data = self.extract_votes()
            if votes_data:
                data_to_save["votes"] = votes_data

        if data_type in {"features", "both"}:
            features_data = self.extract_features()
            if features_data:
                data_to_save["features"] = features_data

        self.save_data(data_to_save, output_format, filename)
        self.stdout.write(self.style.SUCCESS(f"Data saved successfully to {filename}.{output_format}!"))

    def extract_votes(self):
        """Extract the latest vote data."""
        last_vote = Vote.objects.order_by("-timestamp").first()
        if last_vote:
            return {
                "finding_id": last_vote.finding_id,
                "user_id": last_vote.user_id,
                "vote_class": last_vote.vote_class,
                "timestamp": last_vote.timestamp.isoformat(),
            }
        logger.info("No votes found.")
        return None

    def extract_features(self):
        """Extract feature data from Finding objects."""
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
        if findings_data:
            logger.info(f"Extracted {len(findings_data)} findings.")
            return findings_data
        logger.info("No findings available.")
        return None

    def save_data(self, data, output_format, filename):
        """Save the extracted data in the specified format."""
        if not data:
            logger.info("No data to save.")
            return

        current_path = Path(__file__).resolve()
        base_dir = current_path.parent.parent.parent
        output_dir = base_dir / "crivo-metadata"

        output_dir.mkdir(parents=True, exist_ok=True)

        file_path = output_dir / f"{filename}.{output_format}"

        if output_format == "json":
            with file_path.open("w", encoding="utf-8") as json_file:
                json.dump(data, json_file, ensure_ascii=False, indent=4)
            logger.info(f"Data saved to {file_path}.")
        elif output_format == "pickle":
            with file_path.open("wb") as pickle_file:
                pickle.dump(data, pickle_file)
            logger.info(f"Data saved to {file_path}.")
        else:
            logger.error("Invalid output format! Use 'json' or 'pickle'.")


# python manage.py dump_trainning_sets --data_type=features --output_format=json --filename=my_data
