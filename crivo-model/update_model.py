import sys
import json

if len(sys.argv) < 2:
    print("Usage: python3 update_model.py <changed_path>")
    sys.exit(1)

try:
    changed_path = sys.argv[1]
    with open(changed_path, "r") as f:
        data = json.load(f)
    user_id = data.get("user_id")
    user_findings = data.get("user_findings")
except (json.JSONDecodeError, KeyError) as e:
    print(f"Error reading JSON data: {e}")
    sys.exit(1)

for finding_id in user_findings:
    vote = user_findings[finding_id]["vote"]
    title = user_findings[finding_id]["title"]
    date = user_findings[finding_id]["date"]
    description = user_findings[finding_id]["description"]
    severity = user_findings[finding_id]["severity"]
    vuln_id_from_tool = user_findings[finding_id]["vuln_id_from_tool"]
    mitigation = user_findings[finding_id]["mitigation"]
    epss_score = user_findings[finding_id]["epss_score"]
    epss_percentile = user_findings[finding_id]["epss_percentile"]
    cve = user_findings[finding_id]["cve"]