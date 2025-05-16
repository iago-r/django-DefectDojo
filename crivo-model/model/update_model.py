import json
import sys

if len(sys.argv) < 2:
    sys.exit(1)

try:
    changed_path = sys.argv[1]
    with open(changed_path, encoding="utf8") as f:
        data = json.load(f)
    user_id = data.get("user_id")
    user_findings = data.get("user_findings", {})
except (json.JSONDecodeError, KeyError):
    sys.exit(1)

for finding_id, finding in user_findings.items():
    vote = finding.get("vote")
    title = finding.get("title")
    date = finding.get("date")
    description = finding.get("description")
    severity = finding.get("severity")
    vuln_id_from_tool = finding.get("vuln_id_from_tool")
    mitigation = finding.get("mitigation")
    epss_score = finding.get("epss_score")
    epss_percentile = finding.get("epss_percentile")
    cve = finding.get("cve")
