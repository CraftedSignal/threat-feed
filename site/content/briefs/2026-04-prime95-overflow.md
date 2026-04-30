---
title: Prime95 Local Buffer Overflow Vulnerability (CVE-2018-25299)
slug: 2026-04-prime95-overflow
description: Prime95 version 29.4b8 contains a local buffer overflow vulnerability, allowing attackers to execute arbitrary code by exploiting structured exception handling (SEH) mechanisms through a malicious payload in the PrimeNet proxy hostname field.
date: "2026-04-29T20:16:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer-overflow
  - code-execution
  - cve-2018-25299
vendors:
  - Mersenne Research, Inc.
products:
  - Prime95
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2018-25299
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25299
  - https://www.exploit-db.com/exploits/44649
  - https://www.mersenne.org/
  - https://www.mersenne.org/download/#download
  - https://www.vulncheck.com/advisories/prime95-29-4b8-local-buffer-overflow-via-seh
rules:
  - title: Detect Prime95 with Suspicious Proxy Hostname
    description: Detects Prime95 execution with a long proxy hostname, potentially indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Prime95 Execution from Unusual Location
    description: Detects Prime95 execution from locations other than Program Files or Program Files (x86), which may be a sign of suspicious behavior.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Prime95 is a popular application used for finding Mersenne prime numbers, often employed for stress-testing computer hardware. Version 29.4b8 of Prime95 is vulnerable to a local buffer overflow (CVE-2018-25299). An attacker with local access can exploit this vulnerability to execute arbitrary code on the system. The vulnerability stems from insufficient input validation when handling the optional proxy hostname field within the PrimeNet connection settings. By providing an overly long string, an attacker can overwrite parts of the process memory, specifically the Structured Exception Handling (SEH) chain. This allows them to redirect the flow of execution to attacker-controlled code, leading to arbitrary command execution. This vulnerability was published on April 29, 2026, and poses a significant risk to systems running the vulnerable software.

## Attack Chain

1. The attacker gains local access to a system running Prime95 29.4b8.
2. The attacker modifies the PrimeNet connection settings within Prime95.
3. The attacker supplies a malicious payload within the optional "proxy hostname" field, exceeding the expected buffer size.
4. When Prime95 attempts to process the overly long proxy hostname, a buffer overflow occurs.
5. The overflow overwrites the Structured Exception Handling (SEH) record on the stack.
6. When an exception occurs within Prime95 (triggered intentionally or unintentionally), the overwritten SEH record points to attacker-controlled code.
7. The system attempts to handle the exception, causing execution to jump to the attacker-controlled code injected via the proxy hostname.
8. The attacker's code executes with the privileges of the Prime95 process, potentially leading to system compromise.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the affected system. This can lead to complete system compromise, data theft, or installation of malware. Since the vulnerability is local, an attacker needs prior access to the system, either through social engineering, stolen credentials, or other means. However, once access is obtained, exploitation is relatively straightforward. This vulnerability has a high CVSS score of 8.4, reflecting the significant potential impact.

## Recommendation

*   Upgrade to a patched version of Prime95 that addresses CVE-2018-25299. Check the vendor's website (https://www.mersenne.org/download/#download) for updates.
*   Implement strong input validation on any configuration files or settings that Prime95 reads to prevent buffer overflows.
*   Monitor process creation events for unusual activity originating from the Prime95 executable, which could indicate exploitation. Deploy the Sigma rule provided to detect suspicious command line arguments.
