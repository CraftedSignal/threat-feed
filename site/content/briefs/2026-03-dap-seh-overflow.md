---
title: Download Accelerator Plus (DAP) SEH Buffer Overflow Vulnerability
slug: 2026-03-dap-seh-overflow
description: Download Accelerator Plus DAP 10.0.6.0 is vulnerable to a structured exception handler buffer overflow, allowing remote attackers to execute arbitrary code via malicious crafted URLs by overwriting SEH pointers and executing embedded shellcode.
date: "2026-03-24T12:16:02Z"
type: advisory
types:
  - advisory
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
iocs:
  - type: url
    value: http://www.speedbit.com/dap/
  - type: url
    value: http://www.speedbit.com/dap/download/downloading.asp
  - type: url
    value: https://www.exploit-db.com/exploits/46673
  - type: url
    value: https://www.vulncheck.com/advisories/download-accelerator-plus-dap-seh-buffer-overflow
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

Download Accelerator Plus (DAP) version 10.0.6.0 is susceptible to a critical structured exception handler (SEH) buffer overflow vulnerability, identified as CVE-2019-25628. This vulnerability allows remote attackers to achieve arbitrary code execution by crafting malicious URLs. The attack leverages the application's web page import functionality to introduce the malicious URL. Successful exploitation allows attackers to overwrite SEH pointers, redirecting execution flow to attacker-controlled shellcode. This vulnerability poses a significant risk to users of the affected DAP version, potentially leading to complete system compromise. The vulnerability was reported and analyzed by VulnCheck.

## Attack Chain

1.  Attacker crafts a malicious URL containing overflowing buffer data designed to overwrite the SEH pointers.
2.  The victim uses the Download Accelerator Plus 10.0.6.0 application.
3.  The attacker delivers the malicious URL to the victim via social engineering or other means.
4.  The victim imports the malicious URL through the application's web page import functionality.
5.  The application attempts to process the crafted URL, triggering the buffer overflow.
6.  The overflowing buffer overwrites the structured exception handler (SEH) record on the stack.
7.  When an exception occurs, the application attempts to use the overwritten SEH pointer.
8.  Control is transferred to the attacker-controlled shellcode embedded in the malicious URL, leading to arbitrary code execution.

## Impact

Successful exploitation of this vulnerability (CVE-2019-25628) allows a remote attacker to execute arbitrary code on the victim's system. Given the critical severity score (CVSS v3.1: 9.8), the impact is significant. Affected systems are completely compromised, allowing the attacker to install malware, steal sensitive information, or pivot to other systems on the network. The number of potential victims is unknown, but all users of Download Accelerator Plus 10.0.6.0 are at risk.

## Recommendation

*   Discontinue the use of Download Accelerator Plus DAP 10.0.6.0 due to the unpatched SEH buffer overflow vulnerability (CVE-2019-25628).
*   Monitor network traffic for connections to the URLs associated with the vulnerability (e.g., `http://www.speedbit.com/dap/`, `https://www.exploit-db.com/exploits/46673`). Block these domains at the network perimeter.
*   Implement a network detection rule to identify HTTP requests containing unusually long URLs that might be exploiting the buffer overflow. This will require analyzing webserver or proxy logs.
