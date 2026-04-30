---
title: LibreChat SSRF Vulnerability (CVE-2026-31943)
slug: 2026-03-librechat-ssrf
description: LibreChat versions prior to 0.8.3 are vulnerable to Server-Side Request Forgery (SSRF), allowing authenticated users to bypass IP address validation and make the server issue HTTP requests to internal network resources.
date: "2026-03-28T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - ssrf
  - librechat
  - cve-2026-31943
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1110
    technique_name: Server-Side Request Forgery
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31943
  - https://github.com/danny-avila/LibreChat/security/advisories/GHSA-w5r7-4f94-vp4c
ioc_counts:
  ip: 1
rules:
  - title: LibreChat SSRF Attempt via IPv6
    description: Detects potential SSRF attempts in LibreChat by identifying HTTP requests containing IPv4-mapped IPv6 addresses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: LibreChat SSRF Attempt via Private IP Address
    description: Detects potential SSRF attempts in LibreChat by identifying HTTP requests containing private IP addresses (RFC1918).
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

LibreChat, a ChatGPT clone, contains a Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-31943) in versions prior to 0.8.3. The `isPrivateIP()` function in `packages/api/src/auth/domain.ts` fails to properly detect IPv4-mapped IPv6 addresses when they are in their hex-normalized form. This flaw allows an authenticated user to bypass SSRF protection mechanisms and force the LibreChat server to make HTTP requests to internal network resources. These resources include cloud metadata…
