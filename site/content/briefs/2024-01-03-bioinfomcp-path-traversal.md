---
title: florensiawidjaja BioinfoMCP Path Traversal Vulnerability
slug: 2024-01-03-bioinfomcp-path-traversal
description: A path traversal vulnerability in florensiawidjaja BioinfoMCP allows remote attackers to write arbitrary files via manipulation of the 'Name' argument in the Upload function of app.py.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - cve-2026-7398
vendors:
  - florensiawidjaja
products:
  - BioinfoMCP
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7398
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7398
rules:
  - title: Detect BioinfoMCP Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability in BioinfoMCP by identifying requests with path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect BioinfoMCP Upload of Executable Files
    description: Detects the upload of executable files to the BioinfoMCP server, which could be a result of a successful path traversal exploitation.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-7398, affects the BioinfoMCP platform developed by florensiawidjaja. The vulnerability resides in the Upload function within the bioinfo_mcp_platform/app.py file. An attacker can exploit this weakness remotely by manipulating the `Name` argument during file uploads, allowing them to write files to arbitrary locations on the server. This poses a significant security risk, potentially leading to code execution, data compromise, or denial of service. The exploit is publicly available, increasing the likelihood of exploitation. The BioinfoMCP project utilizes continuous delivery with rolling releases, making it difficult to determine specific affected and patched versions. The project has been notified through an issue report, but no response has been received.

## Attack Chain

1. An attacker identifies an accessible BioinfoMCP instance.
2. The attacker crafts a malicious HTTP request targeting the Upload endpoint.
3. Within the request, the 'Name' argument is manipulated to include path traversal sequences (e.g., ../../).
4. The server-side application fails to properly sanitize or validate the 'Name' argument.
5. The application constructs a file path using the attacker-controlled 'Name' argument.
6. The application writes the uploaded file to the attacker-specified location outside of the intended upload directory.
7. The attacker uploads a malicious file (e.g., a web shell or executable).
8. The attacker executes the uploaded file, potentially gaining control of the server.

## Impact

Successful exploitation of this path traversal vulnerability could allow an attacker to overwrite critical system files, execute arbitrary code on the server, and potentially gain complete control of the affected system. Due to the lack of specific versioning and deployment details, the number of potentially affected instances is unknown. However, given the publicly available exploit, any unpatched BioinfoMCP instance is at immediate risk of compromise. The impact includes potential data breaches, service disruption, and reputational damage.

## Recommendation

*   Inspect web server logs for suspicious requests containing path traversal sequences (e.g., `../`) in the `cs-uri-query` targeting the `/app.py` endpoint, activating the Sigma rule `Detect BioinfoMCP Path Traversal Attempt`.
*   Deploy the Sigma rule `Detect BioinfoMCP Upload of Executable Files` to identify potential malicious file uploads following exploitation.
*   Implement strict input validation and sanitization on all user-supplied input, especially the 'Name' argument in the Upload function within the bioinfo_mcp_platform/app.py file, to mitigate CVE-2026-7398.
