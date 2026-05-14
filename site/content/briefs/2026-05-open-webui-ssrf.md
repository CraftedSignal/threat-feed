---
title: Open WebUI SSRF Vulnerability via OAuth Profile Picture URL (CVE-2026-45338)
slug: 2026-05-open-webui-ssrf
description: Open WebUI is vulnerable to Server-Side Request Forgery (SSRF) via the `_process_picture_url()` function in `oauth.py`. The function fetches arbitrary URLs from OAuth `picture` claims without validating the URL, allowing an attacker to force the server to make HTTP requests to internal resources and exfiltrate the full response. This vulnerability requires `ENABLE_OAUTH_SIGNUP=true` or `OAUTH_UPDATE_PICTURE_ON_LOGIN=true` to be exploitable.
date: "2026-05-14T20:23:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - open-webui
  - oauth
  - cve-2026-45338
vendors:
  - open-webui
products:
  - open-webui (<= 0.8.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-24c9-2m8q-qhmh
  - CVE-2026-45338
iocs:
  - type: url
    value: http://host.docker.internal:9000/canary
  - type: url
    value: http://localhost:3000/api/v1/auths/
ioc_counts:
  url: 2
rules:
  - title: Detect Open WebUI SSRF via OAuth Picture URL
    description: Detects CVE-2026-45338 exploitation — Outbound connection to internal resources from Open WebUI server during OAuth profile picture processing.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Open WebUI OAuth Profile Image Exfiltration
    description: Detects exfiltration of data via profile_image_url field in Open WebUI API responses, indicating potential SSRF (CVE-2026-45338).
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - webserver
rules_count: 2
---

A Server-Side Request Forgery (SSRF) vulnerability exists in Open WebUI, specifically in the `_process_picture_url()` function located in `backend/open_webui/utils/oauth.py` around line 1338. This function is responsible for fetching profile pictures from OAuth providers. Due to a missing `validate_url()` call, the function fetches arbitrary URLs from OAuth `picture` claims without proper validation. An attacker can exploit this to force the Open WebUI server to make HTTP requests to internal resources, such as cloud metadata endpoints or internal network services. The vulnerability is triggered during new user OAuth signup or when updating an existing user's picture on login if `OAUTH_UPDATE_PICTURE_ON_LOGIN=true`. Open WebUI versions up to and including 0.8.12 are affected. This vulnerability is identified as CVE-2026-45338.

## Attack Chain

1. The attacker configures a malicious OIDC server that includes a `picture` claim with a URL pointing to an internal resource (e.g., `http://host.docker.internal:9000/canary`).
2. The attacker initiates OAuth signup on the Open WebUI instance by clicking "Continue with [OAuth Provider]" on the login page when `ENABLE_OAUTH_SIGNUP=true`.
3. Open WebUI receives the OAuth response containing the malicious `picture` claim.
4. The `_process_picture_url()` function in `backend/open_webui/utils/oauth.py` is called with the attacker-controlled URL.
5. The function fetches the URL without validation using `aiohttp.ClientSession`.
6. The server fetches the attacker-controlled URL and reads the response.
7. The response is base64-encoded and stored as the user's `profile_image_url`.
8. The attacker can retrieve the base64-encoded data via the `/api/v1/auths/` endpoint, completing the SSRF and allowing exfiltration of the targeted resource's content.

## Impact

Successful exploitation allows an attacker to force the Open WebUI server to make HTTP requests to internal or external resources. This can lead to:

- **Stealing cloud metadata:** Accessing AWS IMDSv1 (`http://169.254.169.254/latest/meta-data/iam/security-credentials/`) to obtain IAM credentials.
- **Accessing internal network services:** Interacting with services not exposed to the internet.
- **Exploiting localhost-bound services:** Interacting with Redis, Elasticsearch, or internal APIs.

The attacker exfiltrates the full HTTP response body via the base64-encoded `profile_image_url` field, providing full-read SSRF capabilities.

## Recommendation

*   Apply the suggested fix by adding `validate_url()` before fetching in the `_process_picture_url` function, as detailed in the advisory, to remediate CVE-2026-45338.
*   Deploy the Sigma rule `Detect Open WebUI SSRF via OAuth Picture URL` to detect attempts to exploit CVE-2026-45338 by monitoring network connections from the Open WebUI server to internal or unexpected external resources.
*   Monitor web server logs for requests containing `userinfo` with suspicious URLs in the `picture` claim to detect potential SSRF attempts, using the IOC `http://host.docker.internal:9000/canary` as a test case.
