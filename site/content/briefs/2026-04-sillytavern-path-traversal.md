---
title: SillyTavern Path Traversal Vulnerability in Chat Endpoints
slug: 2026-04-sillytavern-path-traversal
description: A path traversal vulnerability in SillyTavern versions 1.16.0 and earlier allows an authenticated attacker to read and delete arbitrary files under their user data root by manipulating the avatar_url parameter in the `/api/chats/export` and `/api/chats/delete` endpoints.
date: "2026-04-02T12:00:00Z"
severities:
  - high
tags:
  - path-traversal
  - web-application
  - sillytavern
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/advisories/GHSA-vprr-q85p-79mf
rules:
  - title: Detect SillyTavern Path Traversal Attempt via API Export
    description: Detects attempts to exploit the path traversal vulnerability in the /api/chats/export endpoint by looking for path traversal sequences in the avatar_url parameter.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SillyTavern Path Traversal Attempt via API Delete
    description: Detects attempts to exploit the path traversal vulnerability in the /api/chats/delete endpoint by looking for path traversal sequences in the avatar_url parameter.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SillyTavern requests to sensitive files
    description: Detects requests to sensitive files such as secrets.json and settings.json via the SillyTavern API
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1552.001
    data_sources:
      - webserver
      - linux
rules_count: 3
---

SillyTavern, a local web UI for large language models, is vulnerable to a path traversal attack. This vulnerability, affecting versions 1.16.0 and earlier, stems from insufficient input validation in the `avatar_url` parameter of the `/api/chats/export` and `/api/chats/delete` endpoints. An authenticated attacker can exploit this flaw to read or delete arbitrary files within the user's data directory. The vulnerability exists because the application fails to adequately sanitize path traversal…
