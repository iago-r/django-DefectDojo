from xml.dom import NamespaceErr

from defusedxml import ElementTree as ET
import csv

from dojo.models import Finding


class OpenVASXMLParser:
    def get_findings(self, filename, test):
        findings = []
        tree = ET.parse(filename)
        root = tree.getroot()
        if "report" not in root.tag:
            msg = "This doesn't seem to be a valid Greenbone OpenVAS XML file."
            raise NamespaceErr(msg)
        report = root.find("report")
        results = report.find("results")

        cve_dataset = {}

        with open("/app/crivo-metadata/cve-metadata/epss.csv", encoding="utf-8") as f:
            file_reader = csv.reader(f)
            for row in file_reader:
                if not row[0].startswith("CVE"):
                    continue
                cve_dataset[row[0]] = (row[1], row[2])

        for result in results:
            script_id = None
            for finding in result:
                if finding.tag == "name":
                    title = finding.text
                    description = [f"**Name**: {finding.text}"]
                if finding.tag == "host":
                    title = title + "_" + finding.text
                    description.append(f"**Host**: {finding.text}")
                if finding.tag == "port":
                    title = title + "_" + finding.text
                    description.append(f"**Port**: {finding.text}")
                if finding.tag == "nvt":
                    description.append(f"**NVT**: {finding.text}")
                    script_id = finding.get("oid") or finding.text

                    # capture CVEs
                    refs = finding.find("refs")
                    cve_list = []

                    if refs is not None:
                        cve_list = [ref.get("id") for ref in refs.findall("ref") if ref.get("type") == "cve"]

                    if cve_list:
                        description.append(f"**CVEs**: {', '.join(cve_list)}")

                if finding.tag == "severity":
                    severity = self.convert_cvss_score(finding.text)
                    description.append(f"**Severity**: {finding.text}")
                if finding.tag == "qod":
                    description.append(f"**QOD**: {finding.text}")
                if finding.tag == "description":
                    description.append(f"**Description**: {finding.text}")

            epss_score, epss_percentile, cve = self.get_epss_data(cve_list, cve_dataset)

            finding = Finding(
                title=str(title),
                test=test,
                description="\n".join(description),
                severity=severity,
                dynamic_finding=True,
                static_finding=False,
                vuln_id_from_tool=script_id,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                cve=cve,
            )
            findings.append(finding)
        return findings

    def get_epss_data(self, cve_list: list, cve_dataset: dict):
        # if cve_list is
        if not cve_list:
            return None, None, None

        highest_cve = None
        highest_epss = None
        highest_percentile = None

        for cve in cve_list:
            cve_instance = cve_dataset.get(cve)

            if cve_instance is not None:
                epss = cve_instance[0]
                percentile = cve_instance[1]

                if highest_epss is None or epss > highest_epss:
                    highest_cve = cve
                    highest_epss = epss
                    highest_percentile = percentile

        return highest_epss, highest_percentile, highest_cve

    def convert_cvss_score(self, raw_value):
        val = float(raw_value)
        if val == 0.0:
            return "Info"
        if val < 4.0:
            return "Low"
        if val < 7.0:
            return "Medium"
        if val < 9.0:
            return "High"
        return "Critical"
