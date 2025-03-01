from xml.dom import NamespaceErr

from defusedxml import ElementTree as ET
import pandas as pd

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
        
        df = pd.read_csv("/app/dojo/tools/openvas/epss_scores-2025-02-27.csv", low_memory=False, dtype={'cve': str, 'epss': 'float64', 'percentile': 'float64'})
        
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
                    
                    #capture CVEs
                    refs = finding.find("refs")
                    cve_list = []
                    
                    if refs is not None:
                        cve_list = [ref.get("id") for ref in refs.findall("ref") if ref.get("type") == "cve"]

                if finding.tag == "severity":
                    severity = self.convert_cvss_score(finding.text)
                    description.append(f"**Severity**: {finding.text}")
                if finding.tag == "qod":
                    description.append(f"**QOD**: {finding.text}")
                if finding.tag == "description":
                    description.append(f"**Description**: {finding.text}")

            epss_score, epss_percentile = self.get_epss_data(cve_list, df)
            
            finding = Finding(
                title=str(title),
                test=test,
                description="\n".join(description),
                severity=severity,
                dynamic_finding=True,
                static_finding=False,
                vuln_id_from_tool=script_id,
                epss_score=epss_score,
                epss_percentile=epss_percentile
            )
            findings.append(finding)
        return findings

    def get_epss_data(self, cve_list:list, df: pd.DataFrame):
            
        # if cve_list is
        if not cve_list:
            return None, None
        
        highest_epss = None
        highest_percentile = None
        
        for cve in cve_list:
            cve_instance = df[df["cve"] == cve]
            
            if not cve_instance.empty:
                epss = cve_instance["epss"].values[0]
                percentile = cve_instance["percentile"].values[0]
                
                if highest_epss == None or epss > highest_epss:
                    highest_epss = epss
                    highest_percentile = percentile
                
        return highest_epss, highest_percentile
        
            

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
