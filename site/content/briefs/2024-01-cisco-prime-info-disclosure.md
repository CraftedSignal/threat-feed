---
title: Cisco Prime Infrastructure Information Disclosure Vulnerability
slug: 2024-01-cisco-prime-info-disclosure
description: Cisco Prime Infrastructure is vulnerable to an information disclosure vulnerability, allowing authenticated remote attackers to download arbitrary log files due to insufficient authorization checks.
date: "2026-05-06T16:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - information-disclosure
  - vulnerability
  - cisco
vendors:
  - Cisco
products:
  - Prime Infrastructure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-pi-unauth-infodiscl-LFnLgmey
rules:
  - title: Cisco Prime Infrastructure Log File Download Attempt
    description: Detects attempts to download arbitrary log files from Cisco Prime Infrastructure via crafted URL requests.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1119
    data_sources:
      - webserver
      - linux
  - title: Cisco Prime Infrastructure Unauthorized Log Access
    description: Detects potential unauthorized log file access attempts on Cisco Prime Infrastructure
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1119
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Cisco Prime Infrastructure is susceptible to an information disclosure vulnerability affecting its log file download functionality. This flaw allows an authenticated, remote attacker to download arbitrary log files from the server, potentially exposing sensitive data. The vulnerability stems from inadequate authorization checks within the download service API. Exploitation requires the attacker to have valid credentials for accessing the web-based management interface of the affected device. Cisco has released software updates to remediate this vulnerability. This vulnerability impacts systems where proper access controls are not enforced on log file retrieval processes.

## Attack Chain

1. An attacker obtains valid credentials to access the web-based management interface of the affected Cisco Prime Infrastructure device. This may be achieved through phishing, credential stuffing, or other means.
2. The attacker logs into the Cisco Prime Infrastructure web interface.
3. The attacker identifies the log file download service API endpoint.
4. The attacker crafts a malicious URL request targeting the log file download service API endpoint. The crafted URL is designed to bypass authorization checks.
5. The attacker sends the crafted URL request to the affected device.
6. Due to insufficient authorization checks, the device processes the request and initiates the download of the targeted log file.
7. The attacker downloads the log file, which may contain sensitive information.
8. The attacker analyzes the downloaded log files for sensitive information such as usernames, passwords, API keys, or internal network configurations.

## Impact

Successful exploitation of this vulnerability could lead to the disclosure of sensitive information contained within the downloaded log files. This information could include user credentials, configuration details, and other sensitive data. The number of affected systems depends on the deployment of Cisco Prime Infrastructure within an organization. The impact could range from minor data leakage to significant compromise of sensitive systems, depending on the content of the logs.

## Recommendation

*   Apply the software updates released by Cisco to address this vulnerability immediately.
*   Monitor web server logs for suspicious URL requests targeting the log file download service API, based on the description in this brief.
*   Implement the Sigma rule provided below to detect attempts to exploit this vulnerability based on HTTP request patterns.
*   Review and enforce strict access controls on the Cisco Prime Infrastructure web interface to prevent unauthorized access.
*   Enable enhanced logging on Cisco Prime Infrastructure to capture detailed information about log file download requests for forensic analysis.
