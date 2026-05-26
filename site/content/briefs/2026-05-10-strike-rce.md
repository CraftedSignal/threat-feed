---
title: 10-Strike Network Scanner 3.0 Buffer Overflow Leading to Remote Code Execution
slug: 2026-05-10-strike-rce
description: A buffer overflow vulnerability exists in 10-Strike Network Scanner 3.0, allowing attackers to bypass SafeSEH protections and execute arbitrary code by crafting a malicious payload in the host name or address field and triggering the vulnerability through the Trace route or System information functions.
date: "2026-05-26T13:38:29Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - buffer-overflow
  - rce
  - windows
vendors:
  - 10-strike
products:
  - network scanner
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1213
    technique_name: Data from Information Repository
cves:
  - id: CVE-2018-25345
    cvss: 8.4
    epss: 0.00013
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25345
rules:
  - title: Detect 10-Strike Network Scanner Suspicious Child Process
    description: Detects potential exploitation of 10-Strike Network Scanner via the creation of suspicious child processes, such as cmd.exe or powershell.exe.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect 10-Strike Network Scanner System Information Module Execution
    description: Detects execution of the NetworkScanner system information module which could indicate CVE-2018-25345 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1213
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

10-Strike Network Scanner 3.0 is susceptible to a buffer overflow vulnerability (CVE-2018-25345) within the host name field. Successful exploitation of this vulnerability allows an attacker to bypass SafeSEH protections and execute arbitrary code within the context of the application. The vulnerability can be triggered via the Trace route or System information functions when processing a crafted host name or address field. This poses a significant risk to organizations utilizing this software, as it could lead to unauthorized access, data breaches, or complete system compromise. The vulnerable version is 3.0.

## Attack Chain

1.  The attacker identifies a vulnerable instance of 10-Strike Network Scanner 3.0.
2.  The attacker crafts a malicious payload designed to exploit the buffer overflow in the host name or address field. The payload is crafted to bypass SafeSEH.
3.  The attacker inputs the malicious payload into the host name or address field within the application's interface.
4.  The attacker initiates either the "Trace route" or "System information" function targeting the input containing the malicious payload.
5.  The application attempts to process the input, triggering the buffer overflow.
6.  The crafted payload overwrites the return address on the stack, bypassing SafeSEH protection.
7.  Control is redirected to the attacker-controlled code within the payload.
8.  The attacker achieves arbitrary code execution within the context of the Network Scanner application.

## Impact

Successful exploitation of CVE-2018-25345 can lead to arbitrary code execution, potentially granting an attacker full control over the affected system. This could result in data breaches, malware installation, or further lateral movement within the network. Given the nature of network scanners, successful exploitation could provide attackers with valuable network reconnaissance capabilities, compounding the impact.

## Recommendation

*   Monitor process execution for the creation of child processes from the 10-Strike Network Scanner executable, indicating potential exploitation (see Sigma rule "Detect 10-Strike Network Scanner Suspicious Child Process").
*   Implement network segmentation to limit the potential impact of a successful exploit.
*   While no patch is available, consider migrating to an alternative solution that provides similar functionality without the vulnerability.
