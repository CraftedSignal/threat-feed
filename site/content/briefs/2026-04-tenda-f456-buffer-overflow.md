---
title: Tenda F456 Router Buffer Overflow Vulnerability (CVE-2026-7030)
slug: 2026-04-tenda-f456-buffer-overflow
description: A buffer overflow vulnerability exists in Tenda F456 version 1.0.0.5, specifically affecting the fromRouteStatic function within the /goform/RouteStatic file, which can be exploited remotely by manipulating the 'page' argument.
date: "2026-04-26T10:16:01Z"
severities:
  - critical
tags:
  - cve-2026-7030
  - buffer-overflow
  - router
  - tenda
vendors:
  - Tenda
products:
  - F456 1.0.0.5
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7030
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7030
  - https://github.com/Litengzheng/vuldb_new/blob/main/F456/vul_120/README.md
  - https://vuldb.com/submit/798451
  - https://vuldb.com/vuln/359610
  - https://vuldb.com/vuln/359610/cti
  - https://www.tenda.com.cn/
rules:
  - title: Detect Tenda F456 Buffer Overflow Attempt via Long Page Parameter
    description: Detects attempts to exploit the Tenda F456 buffer overflow vulnerability (CVE-2026-7030) by monitoring for excessively long 'page' parameters in requests to /goform/RouteStatic.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda F456 POST Request to RouteStatic
    description: Detects POST requests to the /goform/RouteStatic endpoint, which is unusual and could indicate an exploitation attempt of CVE-2026-7030.
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

A critical security vulnerability, tracked as CVE-2026-7030, has been identified in Tenda F456 router version 1.0.0.5. The vulnerability resides within the `fromRouteStatic` function of the `/goform/RouteStatic` file. Successful exploitation of this flaw allows a remote attacker to execute arbitrary code due to a buffer overflow. The vulnerability is triggered by manipulating the `page` argument. Publicly available exploit code exists, increasing the risk of widespread exploitation. This…
