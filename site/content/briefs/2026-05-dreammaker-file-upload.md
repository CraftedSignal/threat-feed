---
title: DreamMaker Arbitrary File Upload Vulnerability (CVE-2026-10071)
slug: 2026-05-dreammaker-file-upload
description: Interinfo's DreamMaker is vulnerable to arbitrary file upload (CVE-2026-10071), allowing unauthenticated remote attackers to upload and execute web shell backdoors, leading to arbitrary code execution on the server.
date: "2026-05-29T13:17:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - file upload
  - web shell
  - remote code execution
vendors:
  - Interinfo
products:
  - DreamMaker
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
cves:
  - id: CVE-2026-10071
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10071
  - https://www.twcert.org.tw/en/cp-139-10946-1127f-2.html
  - https://www.twcert.org.tw/tw/cp-132-10943-8fb00-1.html
rules:
  - title: Detects CVE-2026-10071 Exploitation — Web Shell Upload via Unauthenticated File Upload
    description: Detects CVE-2026-10071 exploitation attempt - Uploading suspicious file extensions (e.g., .php, .jsp, .asp) to a web server without authentication.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detects CVE-2026-10071 Exploitation — Web Shell Access After Upload
    description: Detects CVE-2026-10071 exploitation attempt - Accessing a suspicious file extension (e.g., .php, .jsp, .asp) directly after observed file upload activity.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.001
    data_sources:
      - webserver
rules_count: 2
---

Interinfo DreamMaker is vulnerable to an arbitrary file upload vulnerability, tracked as CVE-2026-10071. This vulnerability allows unauthenticated remote attackers to upload and execute web shell backdoors on the server. Successful exploitation leads to arbitrary code execution, potentially allowing the attacker to gain full control over the affected system. This vulnerability was disclosed on May 29, 2026, and poses a significant risk to systems running DreamMaker that are accessible over the network. The lack of authentication makes exploitation straightforward.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP request to the DreamMaker server.
2. The request targets the file upload functionality of the DreamMaker application.
3. The attacker uploads a malicious file, such as a PHP web shell, with an arbitrary file extension.
4. Due to the vulnerability, the server does not properly validate the file type or content.
5. The malicious file is stored on the server's file system in a publicly accessible location.
6. The attacker sends another HTTP request to access the uploaded web shell.
7. The web shell executes, allowing the attacker to run arbitrary commands on the server.
8. The attacker gains full control over the server and can perform actions such as data exfiltration, malware installation, or further lateral movement within the network.

## Impact

Successful exploitation of CVE-2026-10071 allows unauthenticated attackers to execute arbitrary code on the affected DreamMaker server. This can lead to complete system compromise, data theft, and potential disruption of services. Given the ease of exploitation, any DreamMaker instance accessible over the internet is at high risk.

## Recommendation

*   Apply available patches or updates provided by Interinfo to remediate CVE-2026-10071.
*   Implement strict file upload validation mechanisms to prevent the upload of malicious files.
*   Monitor web server logs for suspicious file upload activity and access to unusual file extensions using the provided Sigma rules.
*   Restrict network access to DreamMaker servers to only authorized users and systems.
