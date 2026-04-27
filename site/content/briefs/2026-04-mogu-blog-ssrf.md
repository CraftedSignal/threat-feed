---
title: Moxi Blog v2 <= 5.2 Server-Side Request Forgery Vulnerability
slug: 2026-04-mogu-blog-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in moxi624 Mogu Blog v2 up to version 5.2, specifically affecting the `LocalFileServiceImpl.uploadPictureByUrl` function, allowing remote attackers to potentially interact with internal resources.
date: "2026-04-20T10:16:44Z"
severities:
  - medium
tags:
  - SSRF
  - Mogu Blog
  - CVE-2026-6625
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6625
rules:
  - title: Detect SSRF Attempts via Internal IP in Mogu Blog URL Parameter
    description: Detects potential SSRF attempts in Mogu Blog by identifying requests where the URL parameter (likely used by uploadPictureByUrl) contains internal IP addresses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connections from Mogu Blog Server to Private IP Ranges
    description: Detects network connections originating from the Mogu Blog server to private IP address ranges, which could indicate SSRF exploitation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Moxi Blog v2, a blogging platform, is vulnerable to a server-side request forgery (SSRF) vulnerability (CVE-2026-6625) in versions up to 5.2. The vulnerability resides within the `LocalFileServiceImpl.uploadPictureByUrl` function of the Picture Storage Service component. This flaw allows a remote attacker to potentially force the server to make HTTP requests to arbitrary domains, including internal services, potentially exposing sensitive information or allowing unauthorized actions. The…
