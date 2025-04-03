import json
import logging
import pickle
from pathlib import Path

from django.core.management.base import BaseCommand
from django.db.models import Max

from dojo.models import Finding
from polls_plugin.models import Vote

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = """
    Extract votes or finding data and save them in JSON or Pickle.\n\n

    Usage:\n
      python manage.py dumpo_trainning_sets --data_type=<votes|features> --output_format=<json|pickle> [--filename=<filename>]\n

    Options:\n
      --data_type     Specify the type of data to extract: 'votes' or 'features'.\n
      --output_format Specify the output format: 'json' or 'pickle'.\n
      --filename      Specify the output file name (default: 'output_data').\n\n
    """

    def extract_votes(self):
        """Extract the latest vote for each vulnerability (finding)."""
        latest_votes = Vote.objects.values("finding_id", "user_id").annotate(latest_timestamp=Max("timestamp"))

        if latest_votes:
            votes_data = []
            for vote in latest_votes:
                detailed_vote = Vote.objects.filter(
                    finding_id=vote["finding_id"],
                    user_id=vote["user_id"],
                    timestamp=vote["latest_timestamp"],
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
            return votes_data
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

    def add_arguments(self, parser):
        parser.add_argument(
            "--data_type",
            type=str,
            choices=["votes", "features"],
            help="Specify the type of data to extract: 'votes' or 'features'.",
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

        logger.info(f"Starting command with options: {options}")

        data_type = options["data_type"]
        output_format = options["output_format"]
        filename = options["filename"]

        if data_type == "votes":
            logger.info("Extracting votes...")
            votes_data = self.extract_votes()
            if votes_data:
                filename = f"{filename}_votes"
                self.save_data(votes_data, output_format, filename)
                logger.info("Votes data extracted successfully.")
            else:
                logger.warning("No votes data found.")

        elif data_type == "features":
            logger.info("Extracting features...")
            features_data = self.extract_features()
            if features_data:
                filename = f"{filename}_features"
                self.save_data(features_data, output_format, filename)
                logger.info("Features data extracted successfully.")
            else:
                logger.warning("No features data found.")

        self.stdout.write(self.style.SUCCESS(f"Data saved successfully to {filename}.{output_format}!"))

    def save_data(self, data, output_format, filename):
        """Save the extracted data in the specified format."""
        if not data:
            logger.warning("No data to save.")
            return

        output_dir = Path("/app/crivo-metadata")

        logger.info(f"Creating output directory (if not exists): {output_dir}")
        output_dir.mkdir(parents=True, exist_ok=True)

        file_path = output_dir / f"{filename}.{output_format}"
        logger.info(f"File path to save data: {file_path}")

        if output_format == "json":
            with file_path.open("w", encoding="utf-8") as json_file:
                json.dump(data, json_file, ensure_ascii=False, indent=4)
            logger.info(f"Data saved as JSON at {file_path}")
        elif output_format == "pickle":
            with file_path.open("wb") as pickle_file:
                pickle.dump(data, pickle_file)
            logger.info(f"Data saved as Pickle at {file_path}")
        else:
            logger.error("Invalid output format! Use 'json' or 'pickle'.")
