---
title: Cinny Access Token Disclosure via Malicious Emoji Pack
slug: 2026-05-cinny-token-disclosure
description: A remote authenticated attacker who shares a room with a victim can steal their Matrix access token by injecting a malicious emote pack, exploiting improper URL validation and service worker behavior in Cinny versions prior to 4.10.3.
date: "2026-05-07T16:40:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - web-application
  - token-theft
vendors:
  - GitHub
products:
  - cinny
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-j944-w549-3453
  - https://github.com/cinnyapp/cinny/releases/tag/v4.10.3
rules:
  - title: Detect Suspicious Media Download Request with Authorization Header
    description: Detects network connections with Authorization headers to external media download URLs, indicating potential access token theft.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - network_connection
      - windows
  - title: Detect Arbitrary Avatar URL
    description: Detects webserver requests to arbitrary URLs specified as avatars, potentially indicating malicious avatar injection.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Service Worker Fetching Unauthorized Resources
    description: Detects service worker fetching resources with credentials to domains that are not the homeserver.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

A vulnerability in the Cinny web application allows an attacker to steal a victim's Matrix access token. This occurs when an authenticated attacker who shares a room with a victim and possesses permissions to create room emotes (e.g., in a direct message) injects a malicious emote pack. When the victim opens the emoji or sticker picker for that room, the client sends the victim's Matrix access token to a server controlled by the attacker. This is due to two primary issues: the EmojiBoard component incorrectly uses the untrusted `pack.meta.avatar` field without proper MXC URL validation, allowing arbitrary HTTP(S) URLs, and the service worker unconditionally attaches the user's Authorization token to outbound GET requests containing `/_matrix/client/v1/media/download` or `/_matrix/client/v1/media/thumbnail`, without validating the request host. This enables an attacker to receive the victim's access token via an attacker-controlled URL with permissive CORS. This issue affects Cinny web app versions prior to 4.10.3.

## Attack Chain

1. An attacker gains authenticated access to a Matrix server.
2. The attacker shares a room with the victim (e.g., creates a DM).
3. The attacker uses their permissions to create a custom emote pack within the shared room.
4. The attacker sets the `pack.meta.avatar` field within the emote pack to a malicious URL containing `/_matrix/client/v1/media/download` and hosted on a server they control.
5. The victim opens the emoji or sticker picker within the room.
6. The Cinny client, due to the incorrect fallback in EmojiBoard, uses the attacker-controlled URL from `pack.meta.avatar` without proper validation.
7. The service worker attaches the victim's Authorization header (containing the access token) to the outbound GET request for the malicious URL.
8. The attacker's server, configured with permissive CORS, receives the victim's access token via the Authorization header.

## Impact

Successful exploitation of this vulnerability allows an attacker to steal a victim's Matrix access token. With the stolen token, the attacker can impersonate the victim, access their private messages, join rooms as the victim, and perform actions on their behalf. The scope of impact is limited to users of the Cinny web application prior to version 4.10.3 who interact with rooms containing malicious emote packs.

## Recommendation

*   Upgrade to Cinny version 4.10.3 or later to remediate CVE-2026-42553.
*   Deploy the Sigma rule `Detect Suspicious Media Download Request with Authorization Header` to detect potential exploitation attempts by monitoring network connections with Authorization headers to external media download URLs.
*   Deploy the Sigma rule `Detect Arbitrary Avatar URL` to detect potential exploitation attempts by monitoring webserver logs for requests to arbitrary URLs specified as avatars.
