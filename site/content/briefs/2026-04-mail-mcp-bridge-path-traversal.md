---
title: Path Traversal Vulnerability in mail-mcp-bridge
slug: 2026-04-mail-mcp-bridge-path-traversal
description: A path traversal vulnerability exists in fatbobman mail-mcp-bridge version 1.3.3 and earlier, allowing a remote attacker to read arbitrary files by manipulating the message_ids argument in the src/mail_mcp_server.py file.
date: "2026-04-29T16:16:29Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - path-traversal
  - vulnerability
  - web-application
vendors:
  - fatbobman
products:
  - mail-mcp-bridge
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7386
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7386
rules:
  - title: Detect mail-mcp-bridge Path Traversal Attempt
    description: Detects potential path traversal attempts in mail-mcp-bridge by looking for common path traversal sequences in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect mail-mcp-bridge Path Traversal Attempt in POST Data
    description: Detects potential path traversal attempts in mail-mcp-bridge when the message_ids parameter is sent via POST.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-7386, has been discovered in fatbobman mail-mcp-bridge version 1.3.3 and prior. The vulnerability resides within the `src/mail_mcp_server.py` file, specifically affecting an unspecified function that handles the `message_ids` argument. A remote attacker can exploit this flaw by crafting malicious requests containing manipulated `message_ids` values. Successful exploitation allows the attacker to traverse the file system and potentially read sensitive files. An exploit is publicly available. The vulnerability is addressed in version 1.3.4, with patch `638b162b26532e32fa8d8047f638537dbdfe197a`.

## Attack Chain

1.  The attacker identifies a vulnerable instance of mail-mcp-bridge running version 1.3.3 or earlier.
2.  The attacker crafts a malicious HTTP request targeting the endpoint that processes `message_ids`.
3.  Within the request, the attacker includes a `message_ids` parameter containing path traversal sequences (e.g., `../`).
4.  The server-side application, without proper validation, processes the manipulated `message_ids` value.
5.  The application attempts to access a file path constructed using the attacker-controlled input.
6.  Due to the path traversal sequences, the application accesses a file outside the intended directory.
7.  The application reads the contents of the traversed file.
8.  The attacker retrieves the contents of the file, gaining access to sensitive information.

## Impact

Successful exploitation of this vulnerability allows an attacker to read arbitrary files on the server. This could lead to the exposure of sensitive data such as configuration files, application source code, or user data. With a CVSS v3.1 base score of 7.3, this vulnerability poses a significant risk. The number of affected installations is unknown, but any instance of mail-mcp-bridge running a vulnerable version is susceptible to attack.

## Recommendation

*   Upgrade fatbobman mail-mcp-bridge to version 1.3.4 or later to apply the patch `638b162b26532e32fa8d8047f638537dbdfe197a` that resolves CVE-2026-7386.
*   Deploy the Sigma rule "Detect mail-mcp-bridge Path Traversal Attempt" to identify exploitation attempts in web server logs.
*   Implement input validation on the `message_ids` parameter to prevent path traversal attacks in web applications, even after patching.
