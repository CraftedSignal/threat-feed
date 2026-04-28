---
title: Totolink N300RT Buffer Overflow Vulnerability (CVE-2026-7219)
slug: 2026-04-totolink-n300rt-bo
description: A remote buffer overflow vulnerability exists in Totolink N300RT 3.4.0-B20250430 via manipulation of the 'entry_name' argument in the /boafrm/formIpQoS file, potentially leading to arbitrary code execution.
date: "2026-04-28T04:16:23Z"
severities:
  - high
tags:
  - buffer-overflow
  - iot
  - router
  - cve-2026-7219
vendors:
  - Totolink
products:
  - N300RT
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7219
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7219
  - https://github.com/xiaohaiyang-ai/IoT-Vulnerability-Research/tree/main/Vendors/TOTOLINK/N300RT/formIpQoS-Bof
  - https://vuldb.com/vuln/359819
rules:
  - title: Detect Suspicious Totolink FormIpQoS Requests
    description: Detects abnormally large POST requests to the /boafrm/formIpQoS endpoint which may indicate a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Large POST Requests to Router Config Pages
    description: Detects suspiciously large POST requests to common router configuration pages.  This can indicate exploitation attempts.
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

A buffer overflow vulnerability, identified as CVE-2026-7219, has been discovered in Totolink N300RT router firmware version 3.4.0-B20250430. The vulnerability resides within the `/boafrm/formIpQoS` file and is triggered by manipulating the `entry_name` argument. An attacker can exploit this flaw remotely to potentially execute arbitrary code on the device. Publicly available exploit code exists, increasing the risk of exploitation. This vulnerability poses a significant threat to devices…
