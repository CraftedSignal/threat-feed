---
title: Allok AVI to DVD SVCD VCD Converter Buffer Overflow Vulnerability
slug: 2026-04-allok-buffer-overflow
description: Allok AVI to DVD SVCD VCD Converter 4.0.1217 is vulnerable to a SEH-based buffer overflow, allowing local attackers to execute arbitrary code by providing a malicious string in the License Name field.
date: "2026-04-29T20:16:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer-overflow
  - seh
  - cve-2018-25302
vendors:
  - Allok Soft
products:
  - Allok AVI to DVD SVCD VCD Converter 4.0.1217
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2018-25302
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25302
  - https://www.exploit-db.com/exploits/44549
  - https://www.vulncheck.com/advisories/allok-avi-to-dvd-svcd-vcd-converter-buffer-overflow-seh
rules:
  - title: Allok AVI Converter SEH Buffer Overflow
    description: Detects potential exploitation of the Allok AVI Converter SEH buffer overflow vulnerability by monitoring for the execution of allokconverter.exe with suspicious parent processes often associated with shellcode execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Allok AVI to DVD SVCD VCD Converter version 4.0.1217 is susceptible to a structured exception handling (SEH) based buffer overflow vulnerability. This vulnerability enables a local attacker to execute arbitrary code by crafting a specific payload. The attack involves providing a malicious string in the License Name field of the application. This can be exploited without requiring any prior authentication, making it a significant security concern for systems running the vulnerable software. The vulnerability was reported on April 29, 2026.

## Attack Chain

1.  The attacker prepares a malicious string payload consisting of junk data, an NSEH bypass, an SEH handler address, and shellcode.
2.  The attacker opens the Allok AVI to DVD SVCD VCD Converter application.
3.  The attacker navigates to the registration or license activation section of the software.
4.  The attacker pastes the malicious string into the License Name field.
5.  The attacker clicks the "Register" button, triggering the buffer overflow.
6.  The overflow overwrites the SEH frame, redirecting execution flow to the attacker-controlled NSEH bypass.
7.  The NSEH bypass redirects execution to the SEH handler address, which points to the attacker's shellcode.
8.  The shellcode executes, allowing the attacker to run arbitrary code on the system.

## Impact

Successful exploitation of this buffer overflow vulnerability allows a local attacker to execute arbitrary code with the privileges of the user running the Allok AVI to DVD SVCD VCD Converter. This could lead to complete system compromise, data theft, or installation of malware. Given the ease of exploitation (no authentication required, local access only) this poses a significant risk to systems with the vulnerable software installed.

## Recommendation

*   Deploy the Sigma rule `Allok AVI Converter SEH Buffer Overflow` to detect exploitation attempts based on process creation events.
*   Monitor for abnormal process execution originating from the Allok AVI to DVD SVCD VCD Converter application to identify potential exploitation (process_creation).
*   Consider removing the Allok AVI to DVD SVCD VCD Converter 4.0.1217 until a patch is available, due to the high severity and ease of exploitation.
