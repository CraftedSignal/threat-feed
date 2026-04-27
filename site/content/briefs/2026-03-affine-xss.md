---
title: Critical XSS Vulnerabilities in AFFiNE
slug: 2026-03-affine-xss
description: Two critical XSS vulnerabilities, Reflected XSS in the /image-proxy endpoint and Stored XSS in bookmark cards, were discovered in AFFiNE, a self-hosted alternative to Notion, with the vendor being unresponsive.
date: "2026-03-19T12:09:56Z"
severities:
  - critical
tags:
  - xss
  - vulnerability
  - affine
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.reddit.com/r/cybersecurity/comments/1rxyovl/critical_xss_vulnerabilities_in_affine_are_being/
  - https://gabdevele.dev/posts/2026/multiple-critical-xss-affine/
  - https://github.com/toeverything/AFFiNE/
ioc_counts:
  url: 2
rules:
  - title: Detect Access to AFFiNE Image Proxy Endpoint
    description: Detects access to the AFFiNE /image-proxy endpoint which is vulnerable to reflected XSS.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - zeek
  - title: Detect Bookmark Cards with Javascript Links
    description: Detects bookmark cards containing JavaScript links, indicative of stored XSS vulnerability exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A cybersecurity researcher discovered two critical XSS vulnerabilities in AFFiNE, a self-hosted alternative to Notion, which has 66k stars on GitHub. The vulnerabilities include a reflected XSS in the `/image-proxy` endpoint and a stored XSS vulnerability in bookmark cards. The `/image-proxy` endpoint vulnerability allows unauthenticated users to fetch arbitrary URLs and reflect the URL headers in the response, potentially leaking internal IP addresses. The stored XSS vulnerability enables…
