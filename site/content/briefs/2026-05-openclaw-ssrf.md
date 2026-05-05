---
title: OpenClaw Improper Access Control Leads to SSRF Vulnerability
slug: 2026-05-openclaw-ssrf
description: OpenClaw before 2026.4.14 is vulnerable to server-side request forgery (SSRF) due to improper access control in browser snapshot, screenshot, and tab routes, allowing authenticated attackers to bypass SSRF restrictions and expose internal or disallowed page content.
date: "2026-05-05T12:16:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - access-control
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw
cves:
  - id: CVE-2026-42436
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42436
  - https://github.com/openclaw/openclaw/commit/b75ad800a59009fc47eaa3471410f69046150e59
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-c4qm-58hj-j6pj
  - https://www.vulncheck.com/advisories/openclaw-internal-page-content-exposure-via-browser-snapshot-and-screenshot-routes
rules:
  - title: Detect OpenClaw SSRF Attempt via Navigation
    description: Detects potential SSRF attempts in OpenClaw by monitoring requests to the snapshot, screenshot, or tab routes where the target URL redirects to an internal IP address.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw SSRF Attempt via Internal Hostname
    description: Detects potential SSRF attempts in OpenClaw by monitoring requests to the snapshot, screenshot, or tab routes where the target URL resolves to a local hostname.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

OpenClaw before version 2026.4.14 is susceptible to an improper access control vulnerability that can be exploited to bypass server-side request forgery (SSRF) restrictions. This flaw resides within the browser snapshot, screenshot, and tab routes, where the application fails to consistently validate the final browser target after navigation. An authenticated attacker can manipulate route-driven navigation, without proper policy re-validation, to access internal or otherwise disallowed page content. This vulnerability poses a significant risk to organizations using OpenClaw, as it can lead to the exposure of sensitive information and potentially compromise internal systems.

## Attack Chain

1. An attacker authenticates to the OpenClaw application.
2. The attacker crafts a request to the browser snapshot, screenshot, or tab route with an initial target URL that passes the initial access control checks.
3. The target URL redirects or navigates to an internal or disallowed URL.
4. OpenClaw fails to re-validate the final target URL after the navigation.
5. The application retrieves content from the internal or disallowed URL.
6. OpenClaw displays the content from the internal URL to the attacker.
7. The attacker gains unauthorized access to sensitive information or internal services.

## Impact

Successful exploitation of this vulnerability allows authenticated attackers to bypass SSRF restrictions and gain unauthorized access to internal or disallowed page content. This could lead to the exposure of sensitive information, such as internal configurations, API keys, or customer data. The improper access control could potentially allow an attacker to interact with internal services, leading to further compromise of the affected system and network.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.14 or later to patch the improper access control vulnerability (CVE-2026-42436).
*   Deploy the Sigma rule `Detect OpenClaw SSRF Attempt via Navigation` to identify potential exploitation attempts by monitoring requests to snapshot/screenshot/tab routes.
*   Implement strict input validation and sanitization on all user-supplied URLs to prevent manipulation of route-driven navigation.
