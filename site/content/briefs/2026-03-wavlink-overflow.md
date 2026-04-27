---
title: Wavlink WL-WN579X3-C Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-wavlink-overflow
description: A stack-based buffer overflow vulnerability exists in Wavlink WL-WN579X3-C 231124's UPNP Handler component, specifically in the /cgi-bin/firewall.cgi file and the sub_4019FC function, allowing remote attackers to execute arbitrary code by manipulating the UpnpEnabled argument; public exploits are available, but the vendor has not responded to the disclosure.
date: "2026-03-29T00:00:00Z"
severities:
  - critical
tags:
  - cve
  - buffer-overflow
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5004
  - https://github.com/Litengzheng/vul_db/blob/main/WL-WN579X3-C/vul_200/README.md
  - https://vuldb.com/vuln/353891
rules:
  - title: Detect Suspicious Firewall CGI Requests
    description: Detects HTTP requests to /cgi-bin/firewall.cgi which might indicate exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect UPNP Enabled Overflow
    description: Detects a potentially overflowing UpnpEnabled parameter in a request to /cgi-bin/firewall.cgi
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, identified as CVE-2026-5004, affects the Wavlink WL-WN579X3-C 231124 router. The vulnerability lies within the UPNP Handler component, specifically the `/cgi-bin/firewall.cgi` file's `sub_4019FC` function. By manipulating the `UpnpEnabled` argument, a remote attacker can trigger a stack-based buffer overflow. This can lead to arbitrary code execution on the device. Public exploits for this vulnerability are available, increasing the risk of widespread exploitation…
