---
title: Duartium papers-mcp-server Path Traversal Vulnerability (CVE-2026-7205)
slug: 2026-04-duartium-path-traversal
description: A path traversal vulnerability exists in the `search_papers` function of `src/main.py` in duartium papers-mcp-server version 9ceb3812a6458ba7922ca24a7406f8807bc55598, allowing remote attackers to read arbitrary files by manipulating the `topic` argument, with a public exploit available.
date: "2026-04-28T01:17:16Z"
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

A path traversal vulnerability has been identified in duartium papers-mcp-server, specifically version 9ceb3812a6458ba7922ca24a7406f8807bc55598. The vulnerability resides within the `search_papers` function located in the `src/main.py` file. By manipulating the `topic` argument, a remote attacker can exploit this flaw to traverse the file system and potentially read sensitive files. This vulnerability, identified as CVE-2026-7205, is remotely exploitable and has a publicly available exploit…
