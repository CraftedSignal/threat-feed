---
title: Tenda AC15 Stack-Based Buffer Overflow Vulnerability (CVE-2026-4975)
slug: 2026-03-tenda-ac15-bo
description: A stack-based buffer overflow vulnerability (CVE-2026-4975) exists in the Tenda AC15 router version 15.03.05.19, allowing remote attackers to execute arbitrary code by manipulating the 'funcpara1' argument in a POST request to /goform/setcfm.
date: "2026-03-28T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - tenda
  - router
  - buffer overflow
  - cve-2026-4975
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4975
  - https://lavender-bicycle-a5a.notion.site/Tenda-AC15-setcfm-32153a41781f807b8945dd8920fafc14?source=copy_link
  - https://vuldb.com/?ctiid.353862
  - https://vuldb.com/?id.353862
  - https://vuldb.com/?submit.778261
  - https://www.tenda.com.cn/
rules:
  - title: Detect Tenda AC15 setcfm Buffer Overflow Attempt via POST Request
    description: Detects potential exploitation attempts of the Tenda AC15 stack-based buffer overflow vulnerability (CVE-2026-4975) by monitoring for abnormally long funcpara1 arguments in POST requests to /goform/setcfm.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda AC15 setcfm Access from External IP
    description: Detects access to the Tenda AC15 /goform/setcfm endpoint from an external IP address, which might indicate unauthorized attempts to configure the router remotely.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - firewall
rules_count: 2
---

CVE-2026-4975 is a critical security vulnerability affecting Tenda AC15 routers running firmware version 15.03.05.19. This vulnerability resides in the `formSetCfm` function, specifically within the `/goform/setcfm` file, which handles POST requests. An attacker can exploit a stack-based buffer overflow by sending a crafted POST request with a malicious payload in the `funcpara1` argument. The vulnerability is remotely exploitable, meaning an attacker does not need local access to the device…
