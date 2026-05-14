---
title: Open WebUI Stored XSS Vulnerability via OAuth Profile Picture
slug: 2026-05-open-webui-xss
description: Open WebUI is vulnerable to stored cross-site scripting (XSS) via OAuth profile picture handling, allowing an attacker to inject malicious SVG code and potentially takeover user accounts by exfiltrating JWT tokens.
date: "2026-05-14T20:31:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openwebui:open_webui:*:*:*:*:*:*:*:*
tags:
  - xss
  - stored-xss
  - oauth
  - open-webui
vendors:
  - pip
products:
  - open-webui (<= 0.9.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-64496
    cvss: 7.3
    epss: 0.00139
  - id: CVE-2025-64495
    cvss: 8.7
    epss: 8e-05
references:
  - https://github.com/advisories/GHSA-3wgj-c2hg-vm6q
  - backend/open_webui/utils/oauth.py:1318-1351
  - backend/open_webui/utils/oauth.py:1536-1574
  - backend/open_webui/utils/validate.py:10-36
  - backend/open_webui/models/users.py:575-588
  - backend/open_webui/routers/users.py:504-528
  - backend/open_webui/utils/security_headers.py:16-61
  - CVE-2025-64496
  - CVE-2025-64495
iocs:
  - type: url
    value: https://attacker.example/p.svg
  - type: url
    value: https://attacker.example/x?c=
  - type: url
    value: https://target.example/api/v1/users/<attacker-user-id>/profile/image
ioc_counts:
  url: 3
rules:
  - title: Detect Open WebUI Profile Image XSS via SVG Upload
    description: Detects attempts to upload SVG files as profile images in Open WebUI, which can lead to stored XSS (CVE-2025-64496, CVE-2025-64495, GHSA-3wgj-c2hg-vm6q).
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Open WebUI OAuth Profile Picture with SVG MIME Type
    description: Detects the storage of SVG MIME types in profile images in Open WebUI via the OAuth flow, indicating a potential XSS vulnerability (GHSA-3wgj-c2hg-vm6q).
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

Open WebUI versions 0.9.4 and earlier are vulnerable to a stored cross-site scripting (XSS) attack due to improper validation of profile images when users sign in via OAuth. The application fetches a URL provided in the OAuth `picture` claim, infers the MIME type from the URL extension, and stores it as a data URI without proper sanitization. Specifically, an attacker can host a malicious SVG file and set their profile picture URL to that file. When a victim clicks the link to the attacker's profile image, the browser executes the SVG code, potentially leading to account takeover by exfiltrating the victim's JWT token. This vulnerability is similar to CVE-2025-64496 and CVE-2025-64495, which highlights trust boundary errors in Open WebUI.

## Attack Chain

1. The attacker crafts a malicious SVG file containing JavaScript code to exfiltrate `localStorage.token`.
2. The attacker hosts the malicious SVG file on a publicly accessible server (e.g., `https://attacker.example/p.svg`).
3. The attacker configures their OAuth profile picture URL to point to the malicious SVG file.
4. The attacker signs in to Open WebUI via OAuth, triggering the application to fetch and store the SVG data URI as their profile image.
5. The attacker crafts a URL to their profile image endpoint (e.g., `https://target.example/api/v1/users/<attacker-user-id>/profile/image`) and shares it with a victim.
6. The authenticated victim clicks on the link.
7. The server serves the attacker-controlled SVG with `Content-Type: image/svg+xml` and `Content-Disposition: inline`.
8. The victim's browser renders the SVG, executes the embedded JavaScript, and exfiltrates the victim's JWT token to the attacker's server.

## Impact

Successful exploitation can lead to account takeover of any authenticated user who clicks the malicious link. The attacker can then access the victim's chats, API keys, and potentially achieve remote code execution (RCE) via installed tools if the victim has the `workspace.tools` permission. Furthermore, the lack of SSRF protection allows an attacker to potentially read internal resources by pointing the `picture` claim at internal URLs.

## Recommendation

*   Implement server-side MIME type validation in `_process_picture_url` (`utils/oauth.py:1336-1345`) to only allow `image/png`, `image/jpeg`, `image/gif`, and `image/webp`. Use the `Content-Type` response header instead of the URL extension.
*   Enforce a MIME whitelist in `get_user_profile_image_by_id` (`routers/users.py:504-528`) before building the `StreamingResponse`.
*   Apply the `validate_profile_image_url` validator at the model layer (`Users.update_user_profile_image_url_by_id`), not just at the Pydantic form layer, to ensure all profile image updates are validated.
*   Enable `X-Content-Type-Options: nosniff` and set a default Content Security Policy (CSP) to mitigate XSS attacks by setting the appropriate environment variables.
