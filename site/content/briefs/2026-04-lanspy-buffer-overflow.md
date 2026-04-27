---
title: LanSpy 2.0.1.159 Local Buffer Overflow Vulnerability
slug: 2026-04-lanspy-buffer-overflow
description: LanSpy 2.0.1.159 is vulnerable to a local buffer overflow, allowing an attacker to overwrite the instruction pointer by providing a crafted payload to the scan field, potentially leading to code execution.
date: "2026-04-22T16:16:47Z"
severities:
  - high
tags:
  - buffer-overflow
  - code-execution
  - cve-2018-25268
vendors:
  - lizardsystems
products:
  - LanSpy
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2018-25268
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25268
  - https://lizardsystems.com
  - https://www.exploit-db.com/exploits/45968
  - https://www.vulncheck.com/advisories/lanspy-local-buffer-overflow-via-scan-field
rules:
  - title: Detect LanSpy Buffer Overflow Attempt via CommandLine Length
    description: Detects potential buffer overflow attempts in LanSpy by monitoring process creation events with abnormally long command line arguments targeting the LanSpy executable.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

LanSpy version 2.0.1.159 is susceptible to a local buffer overflow vulnerability (CVE-2018-25268). This vulnerability, reported in April 2026, stems from insufficient input validation within the application's scan field. An attacker, with local access to a vulnerable system, can exploit this flaw by crafting a specific payload designed to overwrite the instruction pointer. This can lead to application crashes or, more seriously, the potential execution of arbitrary code. The vulnerability…
