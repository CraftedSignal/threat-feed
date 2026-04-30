---
title: SillyTavern Path Traversal Vulnerability in Chat Endpoints
slug: 2026-04-sillytavern-path-traversal
description: A path traversal vulnerability in SillyTavern versions 1.16.0 and earlier allows an authenticated attacker to read and delete arbitrary files under their user data root by manipulating the avatar_url parameter in the `/api/chats/export` and `/api/chats/delete` endpoints.
date: "2026-04-02T12:00:00Z"
type: advisory
types:
  - advisory
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

SillyTavern, a local web UI for large language models, is vulnerable to a path traversal attack. This vulnerability, affecting versions 1.16.0 and earlier, stems from insufficient input validation in the `avatar_url` parameter of the `/api/chats/export` and `/api/chats/delete` endpoints. An authenticated attacker can exploit this flaw to read or delete arbitrary files within the user's data directory. The vulnerability exists because the application fails to adequately sanitize path traversal sequences like `..` when constructing file paths. This can lead to the exposure of sensitive information such as `secrets.json` and `settings.json`, or the deletion of crucial user data, particularly in multi-user or remotely-accessible deployments. The vulnerability was patched in version 1.17.0 and assigned CVE-2026-34524.

## Attack Chain

1. The attacker authenticates to the SillyTavern application using valid credentials, obtaining a session cookie and CSRF token.
2. The attacker crafts a malicious HTTP request targeting the `/api/chats/export` or `/api/chats/delete` endpoint.
3. The attacker sets the `avatar_url` parameter in the request body to a path traversal sequence, such as `..`, to navigate outside the intended "chats" directory.
4. In the `/api/chats/export` endpoint, the attacker specifies the `file` parameter to point to the desired file to read, such as `secrets.json`.
5. The server-side application uses `path.join` to concatenate the user's chats directory with the attacker-controlled `avatar_url` and `file` parameters, resulting in path traversal.
6. The application reads the contents of the file specified by the attacker.
7. In the `/api/chats/delete` endpoint, the attacker specifies the `chatfile` parameter to point to the desired file to delete, such as `settings.json`.
8. The application deletes the file specified by the attacker.

## Impact

Successful exploitation of this vulnerability can have significant consequences. Attackers can gain unauthorized access to sensitive configuration files like `secrets.json`, potentially exposing API keys, passwords, and other confidential information. Furthermore, the ability to delete arbitrary files allows attackers to disrupt the application's functionality or even render a user's account unusable by deleting critical files such as `settings.json`. The risk is amplified in multi-user environments or remotely-accessible deployments, where the impact can extend to multiple users.

## Recommendation

*   Upgrade to SillyTavern version 1.17.0 or later to patch CVE-2026-34524.
*   Deploy the Sigma rule "Detect SillyTavern Path Traversal Attempt via API Export" to detect attempts to exploit the `/api/chats/export` endpoint by monitoring for path traversal sequences in the `cs-uri-query` field.
*   Deploy the Sigma rule "Detect SillyTavern Path Traversal Attempt via API Delete" to detect attempts to exploit the `/api/chats/delete` endpoint by monitoring for path traversal sequences in the `cs-uri-query` field.
*   Review web server access logs for unusual requests to `/api/chats/export` or `/api/chats/delete` with suspicious `avatar_url` parameters.
