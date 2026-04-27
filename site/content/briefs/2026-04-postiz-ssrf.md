---
title: Postiz SSRF Vulnerability (CVE-2026-40168)
slug: 2026-04-postiz-ssrf
description: Postiz, an AI social media scheduling tool, is vulnerable to Server-Side Request Forgery (SSRF) in versions prior to 2.21.5, allowing attackers to access internal resources.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - ssrf
  - cve-2026-40168
  - postiz
cves:
  - id: CVE-2026-40168
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40168
  - https://github.com/gitroomhq/postiz-app/commit/30e8b777098157362769226d1b46d83ad616cb06
  - https://github.com/gitroomhq/postiz-app/releases/tag/v2.21.5
  - https://github.com/gitroomhq/postiz-app/security/advisories/GHSA-34w8-5j2v-h6ww
rules:
  - title: Detect Postiz SSRF Attempt via Public Stream Endpoint
    description: Detects potential SSRF attempts targeting the /api/public/stream endpoint in Postiz by identifying requests that redirect to internal IP addresses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: Detect Postiz SSRF Initial Request
    description: Detects initial request to the /api/public/stream endpoint, which might be followed by a redirect to internal resources.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Postiz is an AI-powered social media scheduling tool. Versions prior to 2.21.5 are susceptible to a Server-Side Request Forgery (SSRF) vulnerability, identified as CVE-2026-40168. The vulnerability exists in the `/api/public/stream` endpoint. The application validates the initially supplied URL and blocks direct access to private or internal hosts. However, it fails to re-validate the final destination after HTTP redirects. This flaw enables an attacker to bypass the initial validation by…
