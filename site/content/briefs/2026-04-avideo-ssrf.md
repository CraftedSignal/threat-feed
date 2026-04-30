---
title: WWBN AVideo SSRF Vulnerability via Incomplete CVE-2026-27732 Fix
slug: 2026-04-avideo-ssrf
description: WWBN AVideo is vulnerable to Server-Side Request Forgery (SSRF) due to an incomplete fix for CVE-2026-27732, allowing authenticated uploaders to bypass SSRF protection by providing a `downloadURL` with a common media extension, leading to internal response exfiltration.
date: "2026-04-08T00:08:47Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - ssrf
  - avideo
  - cve-2026-39370
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-27732
    cvss: 8.1
    epss: 0.00036
  - id: CVE-2026-39370
    cvss: 7.1
references:
  - https://github.com/advisories/GHSA-cmcr-q4jf-p6q9
iocs:
  - type: url
    value: http://127.0.0.1:9998/probe.mp4
ioc_counts:
  url: 1
rules:
  - title: Detect AVideo SSRF Attempt via DownloadURL
    description: Detects attempts to exploit the AVideo SSRF vulnerability (CVE-2026-39370) by monitoring requests to the vulnerable endpoint with a suspicious downloadURL.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Internal IP in DownloadURL Parameter
    description: Detects attempts to use internal IP addresses within the downloadURL parameter, indicating a potential SSRF attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, a video-sharing platform, is susceptible to Server-Side Request Forgery (SSRF) vulnerability due to an incomplete patch for CVE-2026-27732. The vulnerability exists in the `objects/aVideoEncoder.json.php` script. An authenticated uploader can provide a malicious `downloadURL` containing a common media extension like `.mp4`, `.jpg`, `.gif`, or `.zip`, bypassing SSRF validation. This allows the attacker to force the server to fetch internal resources. The server fetches the specified URL using `url_get_contents()`, stores the response as media content, and makes it accessible through the `/videos/...` endpoint. This vulnerability, identified as CVE-2026-39370, affects AVideo versions 26.0 and earlier. Exploitation enables exfiltration of sensitive data from internal APIs and services.

## Attack Chain

1. An attacker logs in as a low-privilege authenticated user with upload privileges.
2. The attacker crafts a malicious `downloadURL` pointing to an internal resource (e.g., `http://127.0.0.1:9998/probe.mp4`).
3. The attacker sends a POST request to `/objects/aVideoEncoder.json.php` with the `downloadURL` and a valid `format` parameter (e.g., `mp4`).
4. AVideo's `downloadVideoFromDownloadURL()` function extracts the extension and incorrectly skips `isSSRFSafeURL()` validation due to the allowlisted extension.
5. The server fetches the content from the attacker-controlled `downloadURL` using `url_get_contents()`.
6. The fetched content is written into video storage.
7. The attacker retrieves the media metadata using `GET /objects/videos.json.php?showAll=1` to obtain the `videosURL.mp4.url`.
8. The attacker downloads the media URL and recovers the content from the internal resource.

## Impact

Successful exploitation allows an authenticated uploader to force the AVideo server to fetch internal resources and persist the response as media content. This Server-Side Request Forgery (SSRF) vulnerability allows internal response exfiltration from private APIs, admin endpoints, or other internal services reachable from the application host. The number of potential victims is related to the installations of AVideo with versions less than or equal to 26.0, and the sectors primarily affected are likely media and entertainment, as well as organizations utilizing AVideo for internal video hosting.

## Recommendation

*   Apply `isSSRFSafeURL()` to all `downloadURL` inputs in `objects/aVideoEncoder.json.php`, regardless of file extension to remediate CVE-2026-39370.
*   Deploy the Sigma rule "Detect AVideo SSRF Attempt via DownloadURL" to identify potential exploitation attempts based on requests to `/objects/aVideoEncoder.json.php`.
*   Restrict upload-by-URL functionality to an explicit allowlist of trusted fetch origins.
