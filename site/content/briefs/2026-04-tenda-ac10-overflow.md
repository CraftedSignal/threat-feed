---
title: Tenda AC10 Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-ac10-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-5550) in Tenda AC10 firmware version 16.03.10.10_multi_TDE01 within the /bin/httpd SysToolChangePwd function allows remote attackers to execute arbitrary code.
date: "2026-04-05T08:16:25Z"
severities:
  - critical
tags:
  - cve-2026-5550
  - tenda
  - buffer-overflow
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5550
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5550
  - https://github.com/somanyerrors/tenda-ac10v4-vulnerabilities/blob/main/findings/HIGH-01-getvalue-229-callers.md
  - https://vuldb.com/vuln/355314
rules:
  - title: Detect Tenda AC10 HTTPD Buffer Overflow Attempt
    description: Detects potential attempts to exploit the CVE-2026-5550 buffer overflow vulnerability in Tenda AC10 routers by monitoring HTTP POST requests to /bin/httpd with excessive parameter lengths.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda AC10 HTTPD Access
    description: Detects access to the /bin/httpd endpoint on Tenda AC10 routers.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical stack-based buffer overflow vulnerability, identified as CVE-2026-5550, exists in Tenda AC10 router firmware version 16.03.10.10_multi_TDE01. The vulnerability is located in the `fromSysToolChangePwd` function within the `/bin/httpd` binary. A remote attacker can exploit this flaw to overwrite the stack and potentially execute arbitrary code on the affected device. This is achieved by sending a specially crafted request to the device. Successful exploitation could lead to complete…
