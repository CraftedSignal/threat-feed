---
title: Tenda F451 Stack-Based Buffer Overflow Vulnerability (CVE-2026-6137)
slug: 2026-04-tenda-rce
description: A stack-based buffer overflow vulnerability exists in Tenda F451 version 1.0.0.7_cn_svn7958 allowing remote attackers to execute arbitrary code by overflowing the `wanmode` or `PPPOEPassword` arguments in the `/goform/AdvSetWan` endpoint.
date: "2026-04-13T00:17:16Z"
severities:
  - critical
tags:
  - cve-2026-6137
  - tenda
  - buffer-overflow
  - rce
  - iot
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploit System
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-6137
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6137
  - https://github.com/Jimi-Lab/cve/issues/22
  - https://vuldb.com/vuln/357001
rules:
  - title: Detect Tenda F451 Buffer Overflow Attempt
    description: Detects potential buffer overflow attempts on Tenda F451 routers by monitoring the length of the 'wanmode' or 'PPPOEPassword' parameters in POST requests to '/goform/AdvSetWan'.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda F451 Web Request to AdvSetWan
    description: Detects requests to the /goform/AdvSetWan endpoint on Tenda F451 routers, which is a common target for exploits. This rule can help identify suspicious activity even if it doesn't match known exploit patterns.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-6137 is a critical stack-based buffer overflow vulnerability affecting Tenda F451 routers running firmware version 1.0.0.7_cn_svn7958. The vulnerability resides in the `fromAdvSetWan` function within the `/goform/AdvSetWan` endpoint. By manipulating the `wanmode` or `PPPOEPassword` arguments, a remote attacker can overwrite the stack and potentially execute arbitrary code on the device. The public availability of an exploit increases the risk of widespread exploitation, making it…
