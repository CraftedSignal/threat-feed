---
title: Apache CXF Multiple Vulnerabilities Allow Information Disclosure and SSRF
slug: 2026-03-apache-cxf-vulns
description: A remote attacker can exploit multiple vulnerabilities in Apache CXF to disclose information and perform Server-Side Request Forgery (SSRF) attacks.
date: "2026-03-24T10:20:50Z"
severities:
  - high
tags:
  - apache-cxf
  - ssrf
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2022-2316
rules:
  - title: Detect Outbound Network Connection from CXF Server (Possible SSRF)
    description: Detects outbound network connections initiated from servers running Apache CXF, which may indicate SSRF attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect Access to Sensitive Files from CXF Process
    description: Detects access to sensitive files (e.g., /etc/passwd, /etc/shadow) by processes associated with Apache CXF, indicating potential information disclosure.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Apache CXF is vulnerable to multiple security flaws that can be exploited by remote attackers. Successful exploitation of these vulnerabilities can lead to sensitive information disclosure and Server-Side Request Forgery (SSRF) attacks. While the specifics of these vulnerabilities are not detailed in this brief, defenders should be aware that applications using Apache CXF may be at risk. Given the potential for significant impact, including the exposure of internal data and the ability to proxy…
