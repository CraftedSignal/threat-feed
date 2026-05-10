---
title: TextPattern CMS 4.8.7 Authenticated Remote Code Execution via File Upload (CVE-2021-47943)
slug: 2026-05-textpattern-rce
description: TextPattern CMS 4.8.7 contains a remote code execution vulnerability (CVE-2021-47943) that allows authenticated attackers to execute arbitrary commands by uploading malicious PHP files and accessing them with crafted GET requests.
date: "2026-05-10T13:21:12Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - cve
  - rce
  - file_upload
  - textpattern_cms
vendors:
  - Textpattern
products:
  - TextPattern CMS 4.8.7
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
cves:
  - id: CVE-2021-47943
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47943
  - https://www.exploit-db.com/exploits/49996
  - https://www.exploit-db.com/exploits/50415
  - https://www.vulncheck.com/advisories/textpattern-cms-remote-code-execution-via-file-upload
rules:
  - title: Detect CVE-2021-47943 TextPattern File Upload RCE
    description: Detects CVE-2021-47943 exploitation — HTTP requests to uploaded PHP files in the /textpattern/files/ directory, potentially indicating command execution attempts
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.001
    data_sources:
      - webserver
  - title: Detect TextPattern CMS File Uploads
    description: Detects file uploads to the TextPattern CMS files directory
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

TextPattern CMS 4.8.7 is vulnerable to remote code execution (CVE-2021-47943). This vulnerability allows authenticated attackers to execute arbitrary commands on the underlying server. The attack vector involves exploiting the file upload functionality within the CMS. An attacker with valid user credentials can upload a specially crafted PHP file, effectively a webshell, to the server. Once the file is uploaded, the attacker can then trigger the execution of arbitrary commands by accessing the uploaded file via a direct HTTP request, passing commands as GET parameters. This can lead to complete system compromise.

## Attack Chain

1.  Attacker authenticates to the TextPattern CMS 4.8.7 application with valid credentials.
2.  Attacker navigates to the "Files" section within the content area of the CMS.
3.  Attacker uploads a malicious PHP file (webshell) through the file upload functionality. This file contains PHP code designed to execute system commands.
4.  The CMS saves the uploaded file to the /textpattern/files/ directory.
5.  Attacker crafts a malicious HTTP GET request to access the uploaded PHP file (e.g., /textpattern/files/shell.php).
6.  The GET request includes parameters that are passed to the `system` function within the uploaded PHP file (e.g., /textpattern/files/shell.php?cmd=id).
7.  The server executes the system command specified in the GET parameter via the `system` function.
8.  The output of the executed command is returned to the attacker in the HTTP response, allowing the attacker to gain command execution on the server.

## Impact

Successful exploitation of this vulnerability grants the attacker the ability to execute arbitrary commands on the web server. This could lead to complete compromise of the server, data exfiltration, defacement of the website, or further lateral movement within the network. While the specific number of affected installations is unknown, any TextPattern CMS 4.8.7 instance with authenticated users is potentially vulnerable.

## Recommendation

*   Apply available patches or upgrade to a secure version of TextPattern CMS to remediate CVE-2021-47943.
*   Deploy the Sigma rule "Detect CVE-2021-47943 TextPattern File Upload RCE" to detect attempts to exploit this vulnerability by monitoring for access to uploaded PHP files in the `/textpattern/files/` directory.
*   Implement strict file upload policies, including file type validation and size limits, to prevent the upload of malicious files.
*   Restrict access to the /textpattern/files/ directory to authorized users only.
