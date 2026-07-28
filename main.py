#!/usr/bin/env python3
import os
import datetime
from time import sleep
import requests
from django.utils.html import escape
from deadletterbox import Mailer, ReportBuilder, Palette, TemplateRenderer

# Silencing errors
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

# Neon-purple, occult/terminal hacker theme for the "curse" in Curse Catcher.
CURSECATCHER_PALETTE = Palette("cursecatcher", {
    "bg": "#050014",
    "surface": "#0d0221",
    "surface-alt": "#160a33",
    "header-start": "#1a0533",
    "header-end": "#4b0082",
    "accent": "#b026ff",
    "accent-end": "#7209b7",
    "accent-contrast": "#050014",
    "accent-secondary": "#e0aaff",
    "field-color": "#c77dff",
    "row-stripe": "#120428",
    "card-border": "#b026ff",
    "text": "#c9b8e8",
    "text-strong": "#e0aaff",
    "text-muted": "#6a5a8a",
    "border": "#3c096c",
    "row-hover": "#1f0a3d",
})

MAIL_USERNAME = os.environ.get('GMAIL_EMAIL')
MAIL_PASSWORD = os.environ.get('GMAIL_APP_PASSWORD')
CUTOFF_SCORE = float(os.environ.get('CVSS_CUTOFF_SCORE', 9.0))
NIST_KEY = os.environ.get("NIST_KEY")
BCC_LIST = os.environ.get('BCC_LIST', [])
HOURS_BACK = 24
if BCC_LIST:
    BCC_LIST = BCC_LIST.split(';')
if isinstance(BCC_LIST, str):
    BCC_LIST = []
if not CUTOFF_SCORE:
    CUTOFF_SCORE = 9.0
REPORT_DIR = os.path.abspath("./reports")

def build_finding(cve_dict, cvss_max_base_score) -> dict:
    """
    Flattens a single NVD cve entry and its CVSS metrics into a plain
    dict of fields suitable for a report table row.
    """
    cve_num = cve_dict.get('id', '')
    metrics = cve_dict.get('metrics') or {}
    desc_str = '\n'.join([d.get('value') for d in cve_dict.get(
        'descriptions') if d and d.get('lang') == "en"])
    impact_lines = []
    for cvss_version, cvss_values_list in metrics.items():
        impact_lines.append(f"{cvss_version}:")
        # Get the first one only since they duplicate
        if cvss_values_list:
            cvss_values_dict = cvss_values_list[0]
            for cvss_key, cvss_value in cvss_values_dict.items():
                if cvss_key not in [
                    "source",
                    "type",
                    "cvssData"
                ]:
                    impact_lines.append(f"  {cvss_key}: {cvss_value}")
                if cvss_key == "cvssData":
                    for cvss_data_key, cvss_data_value in cvss_value.items():
                        if cvss_data_key in [
                            "baseSeverity",
                            "attackVector",
                            "attackComplexity",
                            "privilegesRequired",
                            "userInteraction",
                            "confidentialityImpact",
                            "integrityImpact",
                            "availabilityImpact",
                            "exploitabilityScore",
                            "impactScore",
                        ]:
                            impact_lines.append(f"  {cvss_data_key}: {cvss_data_value}")
    references = [d.get('url') for d in (cve_dict.get('references') or [])]
    return {
        "cve_id": cve_num,
        "cve_url": f"https://nvd.nist.gov/vuln/detail/{cve_num}",
        "max_base_score": cvss_max_base_score,
        "source_identifier": cve_dict.get('sourceIdentifier', ''),
        "published": cve_dict.get('published'),
        "modified": cve_dict.get('lastModified'),
        "description": desc_str,
        "impact_lines": impact_lines,
        "references": references,
    }


def parse_and_filter(nist_data_list, cvss_base_minimum) -> list:
    """
    This function opens a nvd json data file and parses it
    to only return back > cvss_base_minimum) findings
    in the last 48 hours that have been published or modified.
    """
    current_datetime = datetime.datetime.now(datetime.UTC)
    findings = []
    for nist_data in nist_data_list:
        cve_dict = nist_data.get('cve')
        metrics = cve_dict.get('metrics')
        if not metrics:
            continue
        cvss_score_list = []
        for _, metric_list in metrics.items():
            for metric_dict in metric_list:
                cvss_data = metric_dict.get('cvssData')
                if cvss_data:
                    cvss_score_list.append(cvss_data)
        cvss_max_base_score = max([d.get('baseScore')
                                    for d in cvss_score_list])
        if cvss_max_base_score >= cvss_base_minimum:
            pub_date = datetime.datetime.strptime(
                cve_dict.get('published'),
                "%Y-%m-%dT%H:%M:%S.%f"
            ).replace(
                tzinfo=datetime.timezone.utc
            )
            if (
                pub_date > (
                        current_datetime -
                        datetime.timedelta(
                            hours=HOURS_BACK
                        )
                    )
                ):
                findings.append(build_finding(cve_dict, cvss_max_base_score))
    return findings


def get_nist_data(startIndex=0, limit=2000, results=[]) -> list:
    """
    gets a full list of CVEs that match the date range.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    headers = {
        "apiKey": NIST_KEY
    }
    utcnow = datetime.datetime.now(datetime.UTC)
    utctimeago = utcnow - datetime.timedelta(hours=HOURS_BACK)
    params = {
        "lastModStartDate": utctimeago.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
        "lastModEndDate": utcnow.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
        "resultsPerPage": limit,
        "startIndex": startIndex
    }
    response_ok = False
    response = requests.get(url, headers=headers, params=params, timeout=300)
    if not response.ok:
        response_ok = True
    while response_ok:
        print(f"Got Response Code: {response.status_code}... Waiting...")
        sleep(10)
        response = requests.get(url, headers=headers, params=params)
        if response.ok:
            response_ok = False
    if response.ok:
        nist_data = response.json()
        nist_vuln_data = nist_data.get('vulnerabilities')
        if nist_vuln_data:
            results.extend(nist_vuln_data)
        if len(nist_vuln_data) == 0:
            return results
        if len(results) < nist_data.get('totalResults'):
            sleep(1)
            get_nist_data(
                startIndex=startIndex + 1,
                limit=limit,
                results=results)
    return results


def build_report(findings, cvss_base_minimum, dt_str) -> tuple:
    """
    Builds a deadletterbox ReportBuilder (one card per CVE finding) and a
    parallel markdown rendition of the same data for the on-disk report.
    """
    report = ReportBuilder(
        title="Curse Catcher",
        subtitle=f"CVEs with CVSS >= {cvss_base_minimum} published in the last {HOURS_BACK}h -- {dt_str}",
        palette=CURSECATCHER_PALETTE,
    )
    markdown_sections = []

    if not findings:
        message = f"No new results matching the criteria in the past {HOURS_BACK} hours"
        report.add_table(
            {"Status": {"Details": message}},
            heading="Summary",
            index_label="Field",
        )
        markdown_sections.append(f"## Summary\n\n{message}\n")

    for finding in findings:
        description_html = escape(finding["description"]).replace("\n", "<br>")
        impact_html = "<br>".join(escape(line) for line in finding["impact_lines"])
        references_html = "<br>".join(
            f'<a href="{escape(url)}">{escape(url)}</a>' for url in finding["references"]
        )
        report.add_table(
            {
                "CVE": {"Details": f'<a href="{finding["cve_url"]}">{finding["cve_id"]}</a>'},
                "Max Base Score": {"Details": finding["max_base_score"]},
                "Source Identifier": {"Details": finding["source_identifier"]},
                "Published": {"Details": finding["published"]},
                "Modified": {"Details": finding["modified"]},
                "Description": {"Details": description_html or "No description available"},
                "Impact": {"Details": impact_html or "No impact data available"},
                "References": {"Details": references_html or "No references available"},
            },
            heading=finding["cve_id"],
            index_label="Field",
        )
        markdown_sections.append(
            f"## {finding['cve_id']}\n\n"
            f"| Field | Details |\n"
            f"| --- | --- |\n"
            f"| CVE | [{finding['cve_id']}]({finding['cve_url']}) |\n"
            f"| Max Base Score | {finding['max_base_score']} |\n"
            f"| Source Identifier | {finding['source_identifier']} |\n"
            f"| Published | {finding['published']} |\n"
            f"| Modified | {finding['modified']} |\n"
            f"| Description | {finding['description'].replace(chr(10), ' ').replace('|', '/')} |\n"
            f"| Impact | {' / '.join(finding['impact_lines']).replace('|', '/')} |\n"
            f"| References | {' '.join(finding['references'])} |\n"
        )

    markdown_body = (
        f"# Curse Catcher\n\n**CVEs with CVSS >= {cvss_base_minimum} -- {dt_str}**\n\n"
        + "\n---\n\n".join(markdown_sections)
    )
    return report, markdown_body


def lambda_handler(event, context) -> None:
    """default function for AWS lambdas"""
    dt_str = datetime.datetime.now().strftime('%Y-%m-%d')
    nist_data_list = get_nist_data(startIndex=0, limit=2000, results=[])
    findings = parse_and_filter(nist_data_list, CUTOFF_SCORE)
    report, markdown_body = build_report(findings, CUTOFF_SCORE, dt_str)

    if not os.path.exists(REPORT_DIR):
        os.mkdir(REPORT_DIR)
    with open(os.path.join(REPORT_DIR, f"{dt_str}.md"), "w") as f:
        f.write(markdown_body)

    email_body = report.build_html(renderer=TemplateRenderer(template_dir=TEMPLATE_DIR))
    mail_obj = Mailer(MAIL_USERNAME, MAIL_PASSWORD)
    email_subject = f"Curse Catcher: {dt_str}"
    mail_obj.send_simple(
        email_subject,
        MAIL_USERNAME,
        to=[MAIL_USERNAME],
        cc=[],
        bcc=BCC_LIST,
        html=email_body,
        attachments=None,
        inline_images=None
    )


if __name__ == "__main__":
    lambda_handler(None, None)
