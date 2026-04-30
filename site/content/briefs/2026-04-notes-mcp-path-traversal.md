---
title: edvardlindelof notes-mcp Path Traversal Vulnerability (CVE-2026-7212)
slug: 2026-04-notes-mcp-path-traversal
description: A path traversal vulnerability exists in edvardlindelof notes-mcp up to version 0.1.4, affecting the notes_mcp.py file, allowing a remote attacker to access sensitive files by manipulating the `root_dir/path` argument.
date: "2026-04-28T02:16:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - CVE-2026-7212
vendors:
  - edvardlindelof
products:
  - notes-mcp (<= 0.1.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7212
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7212
  - https://github.com/edvardlindelof/notes-mcp/
  - https://github.com/edvardlindelof/notes-mcp/issues/2
  - https://vuldb.com/submit/802084
  - https://vuldb.com/vuln/359808
  - https://vuldb.com/vuln/359808/cti
rules:
  - title: Detect notes-mcp Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability (CVE-2026-7212) in edvardlindelof notes-mcp by searching for `../` sequences in the URI.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-7212
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect notes-mcp Path Traversal Exploit (403/404)
    description: Detects potential successful path traversal exploitation attempts by identifying 403/404 responses after path traversal attempts.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-7212
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-7212, affects edvardlindelof notes-mcp version 0.1.4 and earlier. This flaw resides within the `notes_mcp.py` file, where manipulation of the `root_dir/path` argument allows unauthorized access to files and directories outside the intended scope. The vulnerability can be exploited remotely and a proof-of-concept exploit is publicly available, increasing the risk of widespread exploitation. The vendor was notified through an issue report but has not yet responded, making timely patching unlikely. Successful exploitation could lead to sensitive data exposure, potentially compromising the entire application and server.

## Attack Chain

1. An attacker identifies an instance of `notes-mcp` running version 0.1.4 or earlier.
2. The attacker crafts a malicious HTTP request targeting the vulnerable endpoint in `notes_mcp.py`.
3. The crafted request includes a manipulated `root_dir/path` argument containing path traversal sequences (e.g., `../`) to navigate outside the intended directory.
4. The application fails to properly sanitize or validate the `root_dir/path` argument.
5. The application uses the attacker-controlled path to access files or directories on the server's file system.
6. The attacker retrieves sensitive data, such as configuration files, application source code, or user data, by reading arbitrary files on the server.
7. If write access is possible, the attacker may overwrite critical system files.
8. The attacker uses the exposed information to further compromise the system or gain unauthorized access to other resources.

## Impact

Successful exploitation of this path traversal vulnerability can lead to unauthorized access to sensitive files and directories on the affected server. This could result in the disclosure of confidential data, such as user credentials, application source code, or internal configuration details. The vulnerability has a CVSS v3.1 score of 7.3 (HIGH), indicating a significant risk. The number of potential victims is unknown, but any system running the vulnerable version of `notes-mcp` is at risk. The project's lack of response to the vulnerability report suggests that a patch may not be immediately available, increasing the window of opportunity for attackers.

## Recommendation

*   Inspect web server access logs for suspicious requests containing path traversal sequences like `../` in the URI targeting `notes_mcp.py` to identify potential exploitation attempts (see Sigma rule `Detect notes-mcp Path Traversal Attempt`).
*   Deploy the provided Sigma rules to your SIEM to detect exploitation attempts targeting this vulnerability.
*   Monitor network traffic for unusual file access patterns originating from the affected server after potential exploitation.
*   Since a public exploit is available, prioritize patching or mitigating this vulnerability if you are using the affected software, paying close attention to changes in request patterns and ensuring awareness of CVE-2026-7212.
