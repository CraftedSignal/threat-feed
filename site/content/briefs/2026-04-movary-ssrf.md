---
title: Movary SSRF Vulnerability (CVE-2026-40348)
slug: 2026-04-movary-ssrf
description: Movary versions before 0.71.1 are vulnerable to server-side request forgery (SSRF) via the `/settings/jellyfin/server-url-verify` endpoint, allowing authenticated users to probe internal network resources.
date: "2026-04-18T00:16:38Z"
severities:
  - medium
tags:
  - ssrf
  - cve-2026-40348
  - movary
  - web-application
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1539
    technique_name: Uncontrolled Resource Consumption
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40348
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40348
rules:
  - title: Detect Movary SSRF Attempt
    description: Detects attempts to exploit the SSRF vulnerability in Movary by monitoring requests to the /settings/jellyfin/server-url-verify endpoint with suspicious URLs.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
      - T1539
    data_sources:
      - webserver
      - linux
  - title: Detect Movary SSRF Response Code
    description: Detects abnormal HTTP response codes after a request to the /settings/jellyfin/server-url-verify endpoint, indicating a successful SSRF.
    platform: sigma
    severity: low
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
      - T1539
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Movary, a self-hosted web application for tracking and rating movies, is susceptible to a Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-40348) in versions prior to 0.71.1. This flaw allows authenticated users to manipulate the `/settings/jellyfin/server-url-verify` endpoint to initiate server-side HTTP requests to arbitrary internal targets. The application uses the Guzzle HTTP client to send requests based on a user-supplied URL, to which `/system/info/public` is appended. The…
