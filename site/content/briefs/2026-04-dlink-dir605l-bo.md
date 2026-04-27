---
title: D-Link DIR-605L Router Buffer Overflow Vulnerability
slug: 2026-04-dlink-dir605l-bo
description: A remote buffer overflow vulnerability exists in the D-Link DIR-605L version 2.13B01 due to improper handling of the 'curTime' argument in the '/goform/formVirtualServ' POST request handler, potentially allowing attackers to execute arbitrary code.
date: "2026-04-09T21:16:13Z"
severities:
  - critical
tags:
  - dlink
  - router
  - buffer_overflow
  - cve-2026-5979
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5979
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5979
  - https://lavender-bicycle-a5a.notion.site/D-Link-DIR-605L-formVirtualServ-33153a41781f80b496e1de206077bc7e?source=copy_link
  - https://vuldb.com/submit/791852
  - https://vuldb.com/vuln/356533
  - https://vuldb.com/vuln/356533/cti
  - https://www.dlink.com/
rules:
  - title: Detect Suspiciously Long curTime Parameter in D-Link Routers
    description: Detects unusually long 'curTime' parameters in requests to '/goform/formVirtualServ', potentially indicating a buffer overflow attempt on D-Link routers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connections from D-Link Routers
    description: Detects unusual outbound network connections originating from D-Link routers, potentially indicating a compromised device.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - firewall
rules_count: 2
---

A buffer overflow vulnerability, CVE-2026-5979, has been identified in D-Link DIR-605L router with firmware version 2.13B01. The vulnerability resides in the `formVirtualServ` function within the `/goform/formVirtualServ` component, specifically within the POST request handler. By manipulating the `curTime` argument, a remote attacker can trigger a buffer overflow. According to the NVD, an exploit is publicly available, increasing the risk of exploitation. This vulnerability affects end-of-life…
