---
title: Hermes WebUI Arbitrary File Deletion Vulnerability (CVE-2026-6832)
slug: 2026-04-hermes-file-deletion
description: Hermes WebUI is vulnerable to arbitrary file deletion via path traversal in the /api/session/delete endpoint due to insufficient validation of the session_id parameter, allowing authenticated attackers to delete writable JSON files on the host system.
date: "2026-04-22T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-6832
  - path-traversal
  - file-deletion
  - webui
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-6832
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6832
  - https://github.com/nesquena/hermes-webui/commit/3cc5839bf303fa6758bfdac538507407a2929655
  - https://github.com/nesquena/hermes-webui/pull/409
  - https://github.com/nesquena/hermes-webui/pull/412
  - https://github.com/nesquena/hermes-webui/releases/tag/v0.50.132
  - https://github.com/nesquena/hermes-webui/releases/tag/v0.50.32
  - https://www.vulncheck.com/advisories/nesquena-hermes-webui-arbitrary-file-deletion-via-unvalidated-session-id
rules:
  - title: Detect Hermes WebUI Path Traversal in Session Deletion API
    description: Detects path traversal attempts in the session_id parameter of the /api/session/delete endpoint in Hermes WebUI, indicative of CVE-2026-6832 exploitation.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1565
    data_sources:
      - webserver
      - linux
  - title: Detect Hermes WebUI Absolute Path File Deletion
    description: Detects attempts to delete arbitrary files using an absolute path in the session_id parameter of the /api/session/delete endpoint, exploiting CVE-2026-6832.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1565
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Hermes WebUI, a web-based user interface, contains an arbitrary file deletion vulnerability, tracked as CVE-2026-6832. The vulnerability resides in the `/api/session/delete` endpoint. An authenticated attacker can exploit this flaw by supplying a crafted `session_id` parameter containing an absolute path or path traversal sequences. This allows the attacker to bypass the intended `SESSION_DIR` boundary and delete arbitrary files on the server, provided the attacker has write access to those…
