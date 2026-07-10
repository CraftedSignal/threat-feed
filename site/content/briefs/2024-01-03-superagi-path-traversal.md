---
title: TransformerOptimus SuperAGI Path Traversal Vulnerability
slug: 2024-01-03-superagi-path-traversal
description: A path traversal vulnerability (CVE-2026-6615) exists in TransformerOptimus SuperAGI version 0.0.14, allowing remote attackers to read or write arbitrary files via manipulation of the 'Name' argument in the Multipart Upload Handler component.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - vulnerability
vendors:
  - SuperAGI
products:
  - TransformerOptimus SuperAGI
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6615
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6615
rules:
  - title: Detect SuperAGI Path Traversal Attempt via Web Logs
    description: Detects potential path traversal attempts against the SuperAGI Multipart Upload Handler by analyzing web server logs for suspicious URI queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Creation by Web Server (SuperAGI)
    description: Detects creation of files outside the expected upload directory by the web server process, potentially indicating path traversal exploitation in SuperAGI.
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

TransformerOptimus SuperAGI version 0.0.14 is vulnerable to a path traversal vulnerability (CVE-2026-6615) in the Multipart Upload Handler component, specifically affecting the `Upload` function within the `superagi/controllers/resources.py` file. This vulnerability allows a remote attacker to manipulate the `Name` argument to read or write files outside of the intended directory. The vulnerability has been publicly disclosed, and proof-of-concept exploit code is available, increasing the risk of widespread exploitation. The vendor was contacted about the vulnerability but did not respond, suggesting that a patch may not be immediately available. This vulnerability poses a significant risk to systems running affected versions of SuperAGI.

## Attack Chain

1.  The attacker identifies a vulnerable SuperAGI instance running version 0.0.14.
2.  The attacker crafts a malicious HTTP request targeting the Multipart Upload Handler.
3.  Within the request, the attacker manipulates the `Name` argument with a path traversal payload, such as `../../../../etc/passwd`.
4.  The SuperAGI application processes the request without proper sanitization of the `Name` argument.
5.  The application attempts to write or read a file to the path specified in the manipulated `Name` argument.
6.  Due to the path traversal vulnerability, the attacker can read sensitive files, such as configuration files or system files.
7.  Alternatively, the attacker can overwrite existing files or create new files in arbitrary locations, potentially leading to code execution.
8.  The attacker leverages the ability to read/write arbitrary files to compromise the SuperAGI instance or the underlying system.

## Impact

Successful exploitation of this path traversal vulnerability (CVE-2026-6615) can allow attackers to read sensitive files from the SuperAGI server, potentially exposing credentials, API keys, or other confidential information. Attackers can also overwrite critical system files or upload malicious code, leading to arbitrary code execution and complete system compromise. Given the nature of SuperAGI as an AI automation platform, a successful attack could result in the theft or manipulation of sensitive data processed by the platform, as well as the deployment of malicious AI models.

## Recommendation

*   Monitor web server logs for suspicious requests containing path traversal sequences (e.g., `../`, `../../`) in the `cs-uri-query` and `cs-uri-stem` fields, particularly targeting the `superagi/controllers/resources.py` endpoint, using the Sigma rule provided below.
*   Inspect file creation events for files created outside of the expected SuperAGI upload directory, especially if the process creating the files originates from the web server. Use the file creation Sigma rule.
*   Implement input validation and sanitization for the `Name` argument in the Multipart Upload Handler to prevent path traversal attacks. Consider using a whitelist approach to restrict allowed characters and paths.
*   Since a patch is not available, consider deploying a web application firewall (WAF) rule to block requests containing path traversal attempts targeting the vulnerable endpoint.
*   Monitor network traffic for connections originating from the SuperAGI server to unusual or suspicious IP addresses, which could indicate post-exploitation activity.
