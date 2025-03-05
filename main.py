#!/usr/bin/env python3
import os
import re
import datetime
from time import sleep
import requests
from django.utils.html import escape
from api_classes.mail_api import MailAPI

# Silencing errors
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


MAIL_USERNAME = os.environ.get('GMAIL_EMAIL')
MAIL_PASSWORD = os.environ.get('GMAIL_APP_PASSWORD')
CUTOFF_SCORE = float(os.environ.get('CVSS_CUTOFF_SCORE', 9.0))
NIST_KEY = os.environ.get("NIST_KEY")
BCC_LIST = os.environ.get('BCC_LIST', [])
DELIMITER_COUNT = 140
HOURS_BACK = 24
if BCC_LIST:
    BCC_LIST = BCC_LIST.split(';')
if not CUTOFF_SCORE:
    CUTOFF_SCORE = 9.0


def parse_and_filter(nist_data_list, cvss_base_minimum) -> list:
    """
    This function opens a nvd json data file and parses it
    to only return back > cvss_base_minimum) findings
    in the last 48 hours that have been published or modified.
    """
    current_datetime = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    results_list = []
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
            #mod_date = datetime.datetime.strptime(
            #    cve_dict.get('lastModified'),
            #    "%Y-%m-%dT%H:%M:%S.%f"
            #).replace(
            #    tzinfo=datetime.timezone.utc
            #)
            pub_date = datetime.datetime.strptime(
                cve_dict.get('published'),
                "%Y-%m-%dT%H:%M:%S.%f"
            ).replace(
                tzinfo=datetime.timezone.utc
            )
            #if (mod_date > (
            #    current_datetime -
            #   datetime.timedelta(
            #        hours=HOURS_BACK))):
            if (
                pub_date > (
                        current_datetime -
                        datetime.timedelta(
                            hours=HOURS_BACK
                        )
                    )
                ):
                tmp_list = []
                tmp_list.append(
                    f"CVE: {cve_dict.get('id', '')}")
                tmp_list.append(
                    f"CVE Max Base Score: {cvss_max_base_score}")
                tmp_list.append(
                    f"CVE Identifier: {cve_dict.get('sourceIdentifier', '')}")
                tmp_list.append(
                    f"Published: {cve_dict.get('published')}")
                tmp_list.append(
                    f"Modified: {cve_dict.get('lastModified')}")
                desc_str = '\n    '.join([d.get('value') for d in cve_dict.get(
                    'descriptions') if d and d.get('lang') == "en"])
                tmp_list.append(
                    f"Description: \n    {desc_str}")
                tmp_list.append("\nImpact:")
                for cvss_version, cvss_values_list in metrics.items():
                    tmp_list.append(f"    {cvss_version}:")
                    # Get the first one only since they duplicate
                    if cvss_values_list:
                        cvss_values_dict = cvss_values_list[0]
                        for cvss_key, cvss_value in cvss_values_dict.items():
                            if cvss_key not in [
                                "source",
                                "type",
                                "cvssData"
                            ]:
                                tmp_list.append(
                                    f"        {cvss_key}: {cvss_value}")
                            if cvss_key == "cvssData":
                                for cvss_data_key, cvss_data_value in cvss_value.items():
                                    tmp_list.append(
                                        f"        {cvss_data_key}: {cvss_data_value}")
                ref_str = '\n    '.join([d.get('url')
                                        for d in cve_dict.get('references')])
                tmp_list.append(
                    f"\nReferences: \n    {ref_str}")
                results_list.append("\n".join(tmp_list))
    return results_list


def get_nist_data(startIndex=0, limit=2000, results=[]) -> list:
    """
    gets a full list of CVEs that match the date range.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    headers = {
        "apiKey": NIST_KEY
    }
    utcnow = datetime.datetime.utcnow()
    utctimeago = utcnow - datetime.timedelta(hours=HOURS_BACK)
    params = {
        "lastModStartDate": utctimeago.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
        "lastModEndDate": utcnow.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
        "resultsPerPage": limit,
        "startIndex": startIndex
    }
    response = requests.get(url, headers=headers, params=params)
    if response.ok:
        nist_data = response.json()
        nist_vuln_data = nist_data.get('vulnerabilities')
        if nist_vuln_data:
            results.extend(nist_vuln_data)
        if len(results) < nist_data.get('totalResults'):
            sleep(1)
            get_nist_data(
                startIndex=startIndex + 1,
                limit=limit,
                results=results)
    return results


def output_cvss_results(html_linebreaks=False, cvss_base_minimum=9.0) -> str:
    """
    main function that strings together all the above
    into a usable job and prints out the results.
    """
    nist_data_list = get_nist_data(startIndex=0, limit=2000, results=[])
    nist_results_list = parse_and_filter(nist_data_list, cvss_base_minimum)
    if nist_results_list:
        line_delimiter = f"\n{'='*DELIMITER_COUNT}\n"
        results_list = line_delimiter.join(nist_results_list)
    else:
        results_list = f"\n No new results matching the criteria in the past {HOURS_BACK} hours"
    final_result = f"{ '=' * DELIMITER_COUNT }\nCurrent Cutoff CVSS Score: {cvss_base_minimum}\n{ '=' * DELIMITER_COUNT }\n{results_list}"
    final_result = re.sub(r'(\n){3,}', '\n\n', final_result)
    if html_linebreaks:
        final_result = escape(final_result)
        final_result = final_result.replace(
            "\n", "<br>").replace(
            " ", "&nbsp;")
    return final_result


def lambda_handler(event, context) -> None:
    """default function for AWS lambdas"""
    mail_obj = MailAPI(
        mail_username=MAIL_USERNAME,
        mail_password=MAIL_PASSWORD
    )
    email_body = output_cvss_results(
        html_linebreaks=True,
        cvss_base_minimum=CUTOFF_SCORE)
    email_subject = f"CVE Report: {datetime.datetime.now().isoformat()}"
    mail_obj.send_mail(
        email_subject,
        email_body,
        MAIL_USERNAME,
        [
            MAIL_USERNAME
        ],
        [],
        BCC_LIST,
        attachments=[]
    )


if __name__ == "__main__":
    lambda_handler(None, None)
