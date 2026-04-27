---
title: Download Accelerator Plus (DAP) SEH Buffer Overflow Vulnerability
slug: 2026-03-dap-seh-overflow
description: Download Accelerator Plus DAP 10.0.6.0 is vulnerable to a structured exception handler buffer overflow, allowing remote attackers to execute arbitrary code via malicious crafted URLs by overwriting SEH pointers and executing embedded shellcode.
date: "2026-03-24T12:16:02Z"
severities:
  - critical
tags:
  - cve-2019-25628
  - buffer-overflow
  - seh-overflow
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25628
  - http://www.speedbit.com/dap/
  - http://www.speedbit.com/dap/download/downloading.asp
  - https://www.exploit-db.com/exploits/46673
  - https://www.vulncheck.com/advisories/download-accelerator-plus-dap-seh-buffer-overflow
ioc_counts:
  url: 4
rules:
  - title: Detect Access to Exploit-DB URL related to DAP SEH Overflow
    description: Detects HTTP requests to the Exploit-DB URL associated with the Download Accelerator Plus SEH overflow exploit.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Speedbit DAP Download Page
    description: Detects HTTP requests to the Speedbit DAP download page.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Download Accelerator Plus (DAP) version 10.0.6.0 is susceptible to a critical structured exception handler (SEH) buffer overflow vulnerability, identified as CVE-2019-25628. This vulnerability allows remote attackers to achieve arbitrary code execution by crafting malicious URLs. The attack leverages the application's web page import functionality to introduce the malicious URL. Successful exploitation allows attackers to overwrite SEH pointers, redirecting execution flow to attacker-controlled…
