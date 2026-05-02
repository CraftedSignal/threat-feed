---
title: Sunnet CTMS/CPAS Arbitrary File Upload Vulnerability (CVE-2026-7490)
slug: 2026-05-sunnet-file-upload
description: A privileged remote attacker can exploit CVE-2026-7490 in Sunnet CTMS and CPAS to upload and execute web shell backdoors, leading to arbitrary code execution on the server.
date: "2026-05-02T10:16:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-file-upload
  - web-shell
  - code-execution
vendors:
  - Sunnet
products:
  - CTMS
  - CPAS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7490
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7490
  - https://www.twcert.org.tw/en/cp-139-10895-25ca1-2.html
  - https://www.twcert.org.tw/tw/cp-132-10894-1ac1f-1.html
rules:
  - title: Detect Malicious File Uploads to Web Servers
    description: Detects potential malicious file uploads to web servers based on file extension and content type.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Web Shell Access
    description: Detects access to common web shell file names
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-7490 is an arbitrary file upload vulnerability found in Sunnet CTMS and CPAS. Disclosed in May 2026, this vulnerability enables a privileged attacker to upload malicious files, specifically web shell backdoors, to the affected server. This can be achieved remotely, without requiring local system access, given the attacker already possesses valid privileged credentials for the application. Successful exploitation allows the attacker to execute arbitrary code on the server, potentially leading to complete system compromise. This vulnerability poses a significant threat to organizations using these Sunnet products, as it could result in data breaches, service disruption, and other malicious activities.

## Attack Chain

1.  Attacker gains privileged access to the CTMS or CPAS application, either through credential theft, phishing, or other means.
2.  Attacker identifies the file upload functionality within the application.
3.  Attacker crafts a malicious file, such as a PHP web shell, designed to execute arbitrary commands on the server.
4.  Attacker bypasses any client-side file type validation mechanisms.
5.  Attacker uploads the malicious file to the server through the vulnerable file upload endpoint.
6.  The application saves the file to a publicly accessible directory without proper sanitization or validation.
7.  Attacker accesses the uploaded web shell via a web browser.
8.  Attacker uses the web shell to execute arbitrary commands on the server, leading to full system compromise.

## Impact

Successful exploitation of CVE-2026-7490 allows attackers to execute arbitrary code on the affected server. This can lead to a range of malicious activities, including data theft, modification, or destruction, installation of malware, and complete system takeover. Since the vulnerability affects CTMS and CPAS, organizations in sectors utilizing these systems for content or process management are particularly at risk. The vulnerability's high severity allows attackers to quickly gain a foothold and potentially compromise sensitive information or disrupt business operations.

## Recommendation

*   Apply available patches or updates from Sunnet to address CVE-2026-7490.
*   Implement the Sigma rule `Detect Malicious File Uploads to Web Servers` to detect suspicious file uploads based on file extensions and content.
*   Review and harden file upload functionalities within CTMS and CPAS to prevent arbitrary file uploads.
*   Monitor web server logs for access to suspicious files in upload directories, using the `Web Shell Access` Sigma rule.
*   Restrict access to file upload functionalities to only authorized users with appropriate privileges.
