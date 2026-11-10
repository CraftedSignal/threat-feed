---
brief_id: brief-2026-11-10-isatap-router-config
event_id: brief-2026-11-10-isatap-router-config
revision: 1
activity_at: "2026-11-10T02:36:05Z"
title: 'Microsoft Windows: ISATAP Router Configuration'
slug: 2026-11-isatap-router-config
description: Detects the configuration of an ISATAP router on a Windows host, which may indicate unauthorized activity related to IPv6 DNS takeover attacks.
date: "2026-11-10T02:36:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
references:
  - https://www.blackhillsinfosec.com/mitm6-strikes-again-the-dark-side-of-ipv6/
  - https://web.archive.org/web/20250724165855/https://redfoxsec.com/blog/ipv6-dns-takeover/
  - https://www.securityhq.com/blog/malicious-isatap-tunneling-unearthed-on-windows-server/
  - https://medium.com/@ninnesoturan/detecting-ipv6-dns-takeover-a54a6a88be1f
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/system/microsoft_windows_Iphlpsvc/win_system_isatap_router_address_set.yml
rules:
  - title: Detect ISATAP Router Configuration
    description: Detects the configuration of a new ISATAP router on a Windows host via Event ID 4100.
    platform: sigma
    severity: medium
    techniques:
      - T1557
      - T1565.002
    data_sources:
      - windows
      - system
rules_count: 1
---

ISATAP is a Microsoft technology for IPv6 transition. Adversaries may advertise themselves as DHCPv6 servers and set malicious ISATAP routers to intercept traffic. Unauthorized ISATAP configurations should be correlated with network baselines and known legitimate deployments.
