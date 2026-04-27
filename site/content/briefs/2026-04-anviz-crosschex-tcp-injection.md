---
title: Anviz CrossChex Standard TCP Packet Injection Vulnerability
slug: 2026-04-anviz-crosschex-tcp-injection
description: Anviz CrossChex Standard lacks source verification in the client/server channel, enabling TCP packet injection by an attacker on the same network to alter or disrupt application traffic.
date: "2026-04-17T20:16:36Z"
severities:
  - high
tags:
  - cve-2026-40434
  - tcp-injection
  - industrial-control-system
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1040
    technique_name: Network Sniffing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
cves:
  - id: CVE-2026-40434
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40434
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-106-03.json
  - https://www.anviz.com/contact-us.html
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-106-03
ioc_counts:
  email: 1
  url: 3
rules:
  - title: Detect Suspicious TCP Traffic to CrossChex Server
    description: Detects TCP packets to the CrossChex server from unexpected sources, indicating potential packet injection.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1558
    data_sources:
      - network_connection
      - windows
  - title: Detect Connection to Anviz Contact Page
    description: Detects attempts to contact Anviz support which might indicate an exploit attempt.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1598
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Anviz CrossChex Standard is vulnerable to TCP packet injection due to a lack of source verification in the client/server communication channel. This vulnerability, identified as CVE-2026-40434, allows an attacker on the same network to inject malicious TCP packets, potentially leading to alteration or disruption of application traffic. The affected software is CrossChex Standard. This vulnerability was reported by ICS-CERT. Successful exploitation can allow an attacker to manipulate user data…
