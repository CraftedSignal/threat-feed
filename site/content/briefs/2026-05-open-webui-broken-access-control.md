---
title: Open WebUI Broken Access Control Allows Unauthorized Access to Conversations (CVE-2026-45349)
slug: 2026-05-open-webui-broken-access-control
description: Open WebUI versions 0.8.12 and earlier are vulnerable to CVE-2026-45349, a broken access control issue where any user can continue the conversation of another user if they know the Chat ID, by using the /api/chat/completions endpoint with their own API key, allowing unauthorized access to private conversations and information.
date: "2026-05-14T20:26:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - broken-access-control
  - open-webui
  - cloud
vendors:
  - open-webui
products:
  - open-webui (<= 0.8.12)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-gfm2-xm6c-37qc
  - https://github.com/open-webui/open-webui/commit/cf4218e688def6f11d195aeda6665ae5b5376b67
rules:
  - title: Detect CVE-2026-45349 Exploitation — Open WebUI Unauthorized Chat Completion Access
    description: Detects CVE-2026-45349 exploitation — Access to the /api/chat/completions endpoint with a Chat ID that does not belong to the user.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect CVE-2026-45349 Attempt - Open WebUI /api/chat/completions Usage
    description: Detects usage of the /api/chat/completions endpoint in Open WebUI, which could be associated with CVE-2026-45349 exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI versions prior to 0.9.0 contain a broken access control vulnerability that allows unauthorized access to user conversations. Specifically, any authenticated user can continue the conversation of another user if they know the target user's Chat ID. This is because the `/api/chat/completions` endpoint does not properly validate whether the requesting user is authorized to access the specified Chat ID. The issue, identified as CVE-2026-45349, was present in versions up to and including 0.8.12 and was resolved in version 0.9.0, released in April 2026. This vulnerability is particularly concerning in environments where users share a common pipeline model, as it enables unauthorized access to sensitive information within conversations.

## Attack Chain

1. An attacker authenticates to an Open WebUI instance as a normal user.
2. The attacker identifies the Chat ID of a target user, potentially by social engineering or observing URLs.
3. The attacker generates an API key for their own user account within Open WebUI.
4. The attacker crafts a request to the `/api/chat/completions` endpoint, using their own API key.
5. The attacker includes the target user's Chat ID in the request body.
6. Open WebUI fails to validate if the attacker owns or has access to the specified Chat ID.
7. The attacker's request is processed, and they are able to continue the conversation associated with the target Chat ID.
8. The attacker can read existing messages and send new messages within the target user's conversation, potentially gaining access to sensitive information.

## Impact

Successful exploitation of CVE-2026-45349 can lead to unauthorized access to private conversations within Open WebUI. Attackers can read sensitive information, potentially including personal data, confidential business communications, or proprietary information. The vulnerability affects all users of Open WebUI versions 0.8.12 and earlier. If an attacker knows a user's Chat ID (exposed in the URL), they can access and read conversations, gaining access to private information.

## Recommendation

*   Upgrade Open WebUI to version 0.9.0 or later to remediate CVE-2026-45349.
*   Implement the following Sigma rule to detect unauthorized access attempts to the `/api/chat/completions` endpoint targeting other users' Chat IDs.
*   Review Open WebUI access logs for any suspicious activity involving the `/api/chat/completions` endpoint and unusual Chat ID usage.
