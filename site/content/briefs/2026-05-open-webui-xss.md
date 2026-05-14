---
title: Open WebUI Stored XSS Vulnerability via SVG Profile Images (CVE-2026-45314)
slug: 2026-05-open-webui-xss
description: Open WebUI versions 0.9.2 and earlier are vulnerable to stored cross-site scripting (XSS) via SVG images in the profile image URL for channel webhooks (CVE-2026-45314), enabling attackers to inject malicious JavaScript that executes when a user views the webhook profile image, potentially leading to session hijacking and account compromise.
date: "2026-05-14T20:20:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - open-webui
  - cve-2026-45314
  - web-application
vendors:
  - Open WebUI
products:
  - Open WebUI (<= 0.9.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-3856-3vxq-m6fc
  - CVE-2026-45314
rules:
  - title: Detect Open WebUI SVG XSS Attempt
    description: Detects CVE-2026-45314 exploitation — attempts to inject SVG payloads with embedded JavaScript into the profile_image_url parameter when creating or updating webhooks in Open WebUI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Open WebUI Serving SVG Profile Image
    description: Detects Open WebUI serving an SVG profile image, which may indicate exploitation of CVE-2026-45314 if unexpected or originating from untrusted sources.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI, a web-based user interface for interacting with AI models, is vulnerable to a stored cross-site scripting (XSS) vulnerability. The vulnerability, identified as CVE-2026-45314, exists in versions 0.9.2 and earlier. It arises from the ability to set an arbitrary profile image URL for channel webhooks. An attacker can set the `profile_image_url` to a `data:image/svg+xml;base64,...` payload containing malicious JavaScript. When a user views the profile image, the SVG is rendered without sanitization, causing the JavaScript to execute in the user's browser session. This can lead to session hijacking, unauthorized actions, and account compromise. The channel feature must be enabled for exploitation to occur.

## Attack Chain

1. An attacker authenticates to the Open WebUI instance as a low-privilege user.
2. The attacker enables the Channel feature if not already enabled.
3. The attacker creates a new channel.
4. The attacker creates a new webhook for the channel, setting the `profile_image_url` parameter to a `data:image/svg+xml;base64,...` payload containing malicious JavaScript code, such as `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(origin)"></svg>`.
5. The server stores the malicious SVG payload in the database without sanitization.
6. A victim (another user) views the channel or webhook, causing their browser to request the profile image from the endpoint `GET /api/v1/channels/webhooks/{webhook_id}/profile/image`.
7. The server retrieves the stored SVG payload and serves it with the `Content-Type: image/svg+xml` header.
8. The victim's browser executes the embedded JavaScript code in the context of the Open WebUI application, enabling the attacker to perform actions on behalf of the victim.

## Impact

Successful exploitation of this stored XSS vulnerability allows an attacker to execute arbitrary JavaScript code in the context of the victim's Open WebUI session. This can lead to stealing of session tokens or API keys stored in local storage, performing unauthorized actions via same-origin APIs, altering user settings, or potentially pivoting to broader account compromise. Because the malicious payload is persisted in the database, it affects any user who views the malicious profile image until it is removed.

## Recommendation

*   Apply the latest security patches or upgrade to a version of Open WebUI greater than 0.9.2 to remediate CVE-2026-45314.
*   Deploy the Sigma rule "Detect Open WebUI SVG XSS Attempt" to identify attempts to inject malicious SVG payloads into the `profile_image_url` parameter.
*   Implement input validation and sanitization on the server-side to prevent the storage of malicious SVG payloads in the database.
*   Consider disabling the Channel feature if it is not essential to your organization's use of Open WebUI until a patch can be applied.
