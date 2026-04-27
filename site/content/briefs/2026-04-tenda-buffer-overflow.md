---
title: Tenda F456 Router Buffer Overflow Vulnerability (CVE-2026-7097)
slug: 2026-04-tenda-buffer-overflow
description: A buffer overflow vulnerability exists in Tenda F456 version 1.0.0.5 within the fromwebExcptypemanFilter function of the /goform/webExcptypemanFilter component's httpd server, which can be triggered remotely by manipulating the page argument leading to potential remote code execution.
date: "2026-04-27T08:16:02Z"
severities:
  - critical
tags:
  - buffer-overflow
  - router
  - remote-code-execution
  - cve
vendors:
  - Tenda
products:
  - F456
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7097
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7097
rules:
  - title: Detect Tenda F456 Buffer Overflow Attempt via URI Length
    description: Detects potential buffer overflow attempts on Tenda F456 routers by monitoring for abnormally long URI queries targeting the vulnerable endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda F456 Buffer Overflow Attempt via Suspicious Characters
    description: Detects potential buffer overflow attempts by looking for suspicious character sequences within the URI query to the vulnerable endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-7097, has been discovered in Tenda F456 router version 1.0.0.5. The vulnerability resides in the `fromwebExcptypemanFilter` function within the `/goform/webExcptypemanFilter` component of the device's `httpd` server. Successful exploitation of this vulnerability allows a remote attacker to cause a buffer overflow by manipulating the `page` argument, potentially leading to arbitrary code execution on the affected device. Given the public…
