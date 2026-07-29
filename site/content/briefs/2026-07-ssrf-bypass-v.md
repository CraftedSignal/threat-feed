---
title: SSRF Bypass Vulnerability in V Library
slug: 2026-07-ssrf-bypass-v
description: The V library (versions 0.5.2 and below) contains a server-side request forgery (SSRF) bypass vulnerability allowing attackers to circumvent host-based allowlists via URL parsing differentials.
date: "2026-07-29T19:18:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - web-security
vendors:
  - V
products:
  - V (0.5.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The V library ... contains a server-side request forgery (SSRF) bypass vulnerability that allows attackers to circumvent host-based allowlists
    confidence_band: high
cves:
  - id: CVE-2026-67201
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67201
---

The V library, in versions up to and including 0.5.2, is susceptible to a server-side request forgery (SSRF) bypass vulnerability identified as CVE-2026-67201. The vulnerability stems from a parser differential between the net.urllib library used for validating host allowlists and the net.http library used for executing HTTP requests.

An attacker can exploit this by crafting a URL that incorporates a backslash within the authority section of the URL string. During validation, the net.urllib.parse() function interprets the authority in a manner that validates against a trusted, allowlisted host. However, when the net.http.get() function processes the same URL, it normalizes the backslash character, causing the request to be routed to an unintended internal host or private network service. This effectively allows an attacker to bypass security boundaries intended to restrict outbound traffic, facilitating the reconnaissance and interaction with internal-only services. This issue was addressed in commit 85859f0.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to internal network services that are otherwise protected by host-based filtering. This impact is significant in environments where the V library is utilized to perform requests on behalf of users, potentially leading to unauthorized data exposure, interaction with internal APIs, or further exploitation of services behind a firewall or perimeter security.

## Recommendation

1. Upgrade the V library to a version containing the patch for commit 85859f0.
2. Implement strict network-level egress filtering to prevent internal-only services from being reached by the host running the application.
3. Validate and sanitize user-provided URLs using a standardized library that ensures consistent parsing behavior across all application components.
