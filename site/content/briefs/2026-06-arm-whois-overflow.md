---
title: Arm Whois 3.11 Stack-Based Buffer Overflow Vulnerability (CVE-2018-25427)
slug: 2026-06-arm-whois-overflow
description: Arm Whois 3.11 is vulnerable to a stack-based buffer overflow (CVE-2018-25427) allowing remote attackers to execute arbitrary code by providing oversized input to the IP address or domain field.
date: "2026-06-01T22:17:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - buffer-overflow
  - rce
  - CVE-2018-25427
vendors:
  - Arm
products:
  - Whois 3.11
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2018-25427
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25427
  - http://www.armcode.com/
  - http://www.armcode.com/downloads/arm-whois.exe
  - https://www.exploit-db.com/exploits/45796
  - https://www.vulncheck.com/advisories/arm-whois-buffer-overflow-via-seh-overwrite
rules:
  - title: Detect Arm Whois Buffer Overflow Attempt
    description: Detects CVE-2018-25427 exploitation attempt - oversized input to Arm Whois service indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - network_connection
      - windows
  - title: Detect Arm Whois Suspicious Process Creation
    description: Detects unusual process creation originating from the Arm Whois executable, potentially indicating successful exploitation of CVE-2018-25427.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Arm Whois 3.11 is susceptible to a stack-based buffer overflow vulnerability. This flaw allows a remote attacker to execute arbitrary code on a vulnerable system. The vulnerability, identified as CVE-2018-25427, arises from insufficient input validation when processing the IP address or domain field. By supplying an oversized input string exceeding 658 bytes, an attacker can overwrite the structured exception handler (SEH) and gain control of program execution. This vulnerability was disclosed on June 1, 2026. Successful exploitation leads to arbitrary code execution within the context of the application.

## Attack Chain

1.  Attacker identifies a vulnerable Arm Whois 3.11 instance.
2.  Attacker crafts a malicious input string exceeding 658 bytes. This string includes shellcode designed to execute arbitrary commands on the target system.
3.  The attacker sends the malicious input to the Arm Whois application, targeting the IP address or domain field.
4.  The Arm Whois application receives the input and attempts to process it without proper bounds checking.
5.  The oversized input overflows the stack buffer, overwriting the Structured Exception Handler (SEH) pointer.
6.  When an exception occurs (triggered intentionally or unintentionally), the application attempts to use the overwritten SEH pointer.
7.  The execution flow is redirected to the attacker-controlled shellcode.
8.  The shellcode executes, granting the attacker arbitrary code execution within the context of the Arm Whois application, potentially leading to full system compromise.

## Impact

Successful exploitation of CVE-2018-25427 allows remote attackers to execute arbitrary code on systems running Arm Whois 3.11. This could lead to complete system compromise, data theft, or denial of service. Given the severity of the vulnerability (CVSS 9.8), it poses a significant risk to organizations using the affected software. The attacker gains full control of the vulnerable host.

## Recommendation

*   Apply available patches or upgrade to a supported version of Arm Whois to remediate CVE-2018-25427.
*   Deploy the Sigma rule `Detect Arm Whois Buffer Overflow Attempt` to detect attempts to exploit this vulnerability via oversized input.
*   Monitor network traffic for unusually long strings being sent to Arm Whois services, which could indicate exploitation attempts.
