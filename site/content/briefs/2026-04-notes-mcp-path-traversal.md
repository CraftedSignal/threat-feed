---
title: edvardlindelof notes-mcp Path Traversal Vulnerability (CVE-2026-7212)
slug: 2026-04-notes-mcp-path-traversal
description: A path traversal vulnerability exists in edvardlindelof notes-mcp up to version 0.1.4, affecting the notes_mcp.py file, allowing a remote attacker to access sensitive files by manipulating the `root_dir/path` argument.
date: "2026-04-28T02:16:08Z"
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

A path traversal vulnerability, identified as CVE-2026-7212, affects edvardlindelof notes-mcp version 0.1.4 and earlier. This flaw resides within the `notes_mcp.py` file, where manipulation of the `root_dir/path` argument allows unauthorized access to files and directories outside the intended scope. The vulnerability can be exploited remotely and a proof-of-concept exploit is publicly available, increasing the risk of widespread exploitation. The vendor was notified through an issue report but…
