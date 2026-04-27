---
title: WWBN AVideo SSRF Vulnerability via Incomplete CVE-2026-27732 Fix
slug: 2026-04-avideo-ssrf
description: WWBN AVideo is vulnerable to Server-Side Request Forgery (SSRF) due to an incomplete fix for CVE-2026-27732, allowing authenticated uploaders to bypass SSRF protection by providing a `downloadURL` with a common media extension, leading to internal response exfiltration.
date: "2026-04-08T00:08:47Z"
severities:
  - high
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

WWBN AVideo, a video-sharing platform, is susceptible to Server-Side Request Forgery (SSRF) vulnerability due to an incomplete patch for CVE-2026-27732. The vulnerability exists in the `objects/aVideoEncoder.json.php` script. An authenticated uploader can provide a malicious `downloadURL` containing a common media extension like `.mp4`, `.jpg`, `.gif`, or `.zip`, bypassing SSRF validation. This allows the attacker to force the server to fetch internal resources. The server fetches the specified…
