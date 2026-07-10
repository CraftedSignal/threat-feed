---
title: PromtEngineer localGPT Unrestricted Upload Vulnerability (CVE-2026-5001)
slug: 2024-01-localgpt-upload
description: A remote attacker can exploit an unrestricted file upload vulnerability (CVE-2026-5001) in PromtEngineer localGPT up to version 4d41c7d1713b16b216d8e062e51a5dd88b20b054 via the do_POST function in backend/server.py.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - unrestricted-upload
  - remote-code-execution
  - localGPT
vendors:
  - PromtEngineer
products:
  - localGPT
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5001
rules:
  - title: Detect Suspicious POST Requests to localGPT backend/server.py with File Upload
    description: Detects POST requests to the backend/server.py endpoint of localGPT with Content-Type indicating file upload, which could indicate exploitation of CVE-2026-5001.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect File Creation in Upload Directory by Web Server Process
    description: Detects file creation events in a typical web server upload directory by the web server process, which may indicate successful exploitation of an upload vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1105
    data_sources:
      - file_event
      - linux
rules_count: 2
---

PromtEngineer localGPT is vulnerable to an unrestricted file upload vulnerability (CVE-2026-5001) affecting versions up to commit 4d41c7d1713b16b216d8e062e51a5dd88b20b054. The vulnerability resides in the `do_POST` function within the `backend/server.py` file. This flaw allows a remote attacker to upload arbitrary files to the server without proper validation, potentially leading to remote code execution or other malicious activities. The exploit is publicly available, increasing the risk of exploitation. The vendor has not responded to vulnerability disclosures. This vulnerability poses a significant risk to organizations utilizing vulnerable versions of localGPT, potentially allowing attackers to compromise the system and gain unauthorized access.

## Attack Chain

1.  The attacker identifies a vulnerable localGPT instance running a version up to 4d41c7d1713b16b216d8e062e51a5dd88b20b054.
2.  The attacker crafts a malicious HTTP POST request targeting the `backend/server.py` endpoint.
3.  The POST request includes a file upload component with a file containing malicious code (e.g., a reverse shell).
4.  The `do_POST` function in `backend/server.py` processes the request without proper validation of the file type or content.
5.  The malicious file is written to a publicly accessible directory on the server.
6.  The attacker sends another HTTP request to execute the uploaded malicious file.
7.  The malicious code executes, granting the attacker a reverse shell or other means of remote access.
8.  The attacker leverages the gained access to compromise the system further, potentially leading to data exfiltration or other malicious activities.

## Impact

Successful exploitation of this vulnerability allows attackers to upload and execute arbitrary files on the affected system, potentially leading to complete system compromise. This can result in data breaches, service disruption, or the deployment of malware. Given the nature of localGPT, which often handles sensitive data, the impact of a successful attack could be significant. The specific number of affected systems and sectors is currently unknown due to the limited information available.

## Recommendation

*   Monitor web server logs for suspicious POST requests targeting the `backend/server.py` endpoint with file upload attempts. Use the provided Sigma rule to detect potential exploitation attempts (Log Source: webserver, product: linux/windows).
*   Implement strict file type and content validation on the server to prevent the upload of malicious files.
*   Apply a web application firewall (WAF) rule to block known exploit patterns targeting CVE-2026-5001.
*   Upgrade to a patched version of localGPT, if available, or implement compensating controls until a patch is released.
*   Review and restrict access controls to the file upload directory to minimize the impact of successful uploads.
