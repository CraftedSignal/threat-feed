---
title: Duartium papers-mcp-server Path Traversal Vulnerability (CVE-2026-7205)
slug: 2026-04-duartium-path-traversal
description: A path traversal vulnerability exists in the `search_papers` function of `src/main.py` in duartium papers-mcp-server version 9ceb3812a6458ba7922ca24a7406f8807bc55598, allowing remote attackers to read arbitrary files by manipulating the `topic` argument, with a public exploit available.
date: "2026-04-28T01:17:16Z"
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
  - duartium
products:
  - papers-mcp-server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7205
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7205
  - https://github.com/duartium/papers-mcp-server/
  - https://github.com/duartium/papers-mcp-server/issues/1
  - https://vuldb.com/submit/802080
  - https://vuldb.com/vuln/359805
  - https://vuldb.com/vuln/359805/cti
rules:
  - title: Detect Path Traversal Attempt in papers-mcp-server
    description: Detects path traversal attempts targeting the `search_papers` function in duartium papers-mcp-server by looking for common path traversal sequences in the URI query.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Path Traversal with URL Encoding in papers-mcp-server
    description: Detects path traversal attempts using URL encoded sequences in the URI query, targeting `search_papers`.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability has been identified in duartium papers-mcp-server, specifically version 9ceb3812a6458ba7922ca24a7406f8807bc55598. The vulnerability resides within the `search_papers` function located in the `src/main.py` file. By manipulating the `topic` argument, a remote attacker can exploit this flaw to traverse the file system and potentially read sensitive files. This vulnerability, identified as CVE-2026-7205, is remotely exploitable and has a publicly available exploit, increasing the risk of widespread exploitation. The project maintainers were notified, but there has been no response or patch released, making immediate defensive measures critical for organizations using this software.

## Attack Chain

1.  The attacker identifies a vulnerable instance of duartium papers-mcp-server version 9ceb3812a6458ba7922ca24a7406f8807bc55598.
2.  The attacker crafts a malicious HTTP request targeting the `search_papers` function.
3.  Within the HTTP request, the attacker injects a path traversal payload into the `topic` argument, such as "../../etc/passwd".
4.  The server-side application, without proper sanitization, processes the malicious `topic` argument.
5.  The application attempts to read the file specified by the attacker's path traversal payload (e.g., /etc/passwd).
6.  The server responds with the contents of the requested file, effectively leaking sensitive information to the attacker.
7.  The attacker analyzes the leaked file for sensitive data, such as usernames, passwords, or configuration details.
8.  The attacker uses the obtained information to further compromise the system or network.

## Impact

Successful exploitation of this path traversal vulnerability allows attackers to read arbitrary files on the affected server. This could lead to the disclosure of sensitive configuration files, user credentials, or source code, potentially leading to further compromise, lateral movement within the network, and data breaches. The lack of a patch and the availability of a public exploit increases the likelihood of widespread exploitation and potential damage.

## Recommendation

*   Deploy the Sigma rule provided in this brief to detect exploitation attempts against the `search_papers` endpoint, focusing on path traversal payloads in the `topic` parameter.
*   Implement input validation and sanitization on the `topic` parameter within the `search_papers` function to prevent path traversal attacks.
*   Monitor web server logs for suspicious requests containing path traversal sequences like "../" and "./" in the URI query to detect potential exploitation attempts.
*   Apply rate limiting to the `search_papers` endpoint to mitigate potential brute-force path traversal attempts.
