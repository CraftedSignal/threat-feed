---
title: Typecho <= 1.3.0 Server-Side Request Forgery Vulnerability (CVE-2026-7025)
slug: 2026-04-typecho-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in Typecho up to version 1.3.0, allowing remote attackers to manipulate the X-Pingback/link argument in the Service::sendPingHandle function to potentially make arbitrary HTTP requests.
date: "2026-04-26T08:17:46Z"
severities:
  - medium
tags:
  - ssrf
  - cve-2026-7025
  - typecho
vendors:
  - Typecho
products:
  - Typecho (<= 1.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7025
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7025
  - https://vuldb.com/submit/797772
  - https://vuldb.com/vuln/359605
  - https://vuldb.com/vuln/359605/cti
  - https://wang1rrr.github.io/2026/03/04/CVE-Report-Typecho-v1-3-0-SSRF/
rules:
  - title: Detect Suspicious X-Pingback Header
    description: Detects suspicious outbound connections initiated by a web server due to a manipulated X-Pingback header, indicating a potential SSRF vulnerability exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Typecho SSRF - External URL in X-Pingback Header
    description: Detects potential SSRF attempts in Typecho by monitoring for X-Pingback headers containing URLs pointing to external domains.
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

Typecho is vulnerable to a server-side request forgery (SSRF) vulnerability (CVE-2026-7025) affecting versions up to 1.3.0. The vulnerability resides in the `Service::sendPingHandle` function within the `var/Widget/Service.php` file, specifically impacting the Ping Back Service Endpoint component. An attacker can remotely trigger this vulnerability by manipulating the `X-Pingback/link` argument. Publicly available exploits exist, increasing the risk of exploitation. The vendor was notified but…
