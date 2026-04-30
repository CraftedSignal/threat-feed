---
title: Snes9K 0.0.9z Buffer Overflow Vulnerability (CVE-2018-25251)
slug: 2026-04-snes9k-overflow
description: Snes9K 0.0.9z is vulnerable to a buffer overflow in the Netplay Socket Port Number field, enabling local attackers to execute arbitrary code via a crafted payload.
date: "2026-04-04T14:16:21Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - buffer-overflow
  - code-execution
  - cve-2018-25251
  - snes9k
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2018-25251
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25251
  - https://sourceforge.net/projects/snes9k/
  - https://sourceforge.net/projects/snes9k/files/latest/download
  - https://www.exploit-db.com/exploits/45598
  - https://www.vulncheck.com/advisories/snes9k-9z-buffer-overflow-seh-via-netplay-socket
rules:
  - title: Snes9K Execution Followed by Unusual Process Creation
    description: Detects Snes9K execution followed by the creation of suspicious processes, potentially indicating code execution from a buffer overflow.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Snes9K Config Write Followed by Execution
    description: Detects modifications to Snes9K configuration files followed by execution of the Snes9K executable. This is to detect scenarios where a config file is modified to exploit the vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Snes9K version 0.0.9z contains a buffer overflow vulnerability (CVE-2018-25251) within the Netplay functionality. Specifically, the application fails to properly validate the size of user-supplied input for the "Netplay Socket Port Number" field. By exploiting this vulnerability, a local attacker can overwrite the Structured Exception Handler (SEH) chain. Successful exploitation allows an attacker to execute arbitrary code within the context of the running Snes9K application, potentially leading to complete system compromise. The vulnerability resides within the Netplay Options menu, accessible from the Snes9K interface.

## Attack Chain

1.  The attacker gains local access to a system with Snes9K 0.0.9z installed.
2.  The attacker opens the Snes9K application.
3.  The attacker navigates to the "Netplay Options" menu within the application.
4.  The attacker locates the "Netplay Socket Port Number" field.
5.  The attacker crafts a malicious payload designed to overwrite the SEH chain. This payload includes the address of the attacker's shellcode.
6.  The attacker pastes the malicious payload into the "Netplay Socket Port Number" field, exceeding the expected buffer size.
7.  The application attempts to handle the overflow, triggering the SEH.
8.  The SEH is overwritten by the attacker's payload, redirecting execution to the attacker's shellcode. This results in arbitrary code execution.

## Impact

Successful exploitation of this buffer overflow vulnerability allows a local attacker to execute arbitrary code on the affected system. This could lead to complete system compromise, including data theft, installation of malware, and further lateral movement within the network. While the vulnerability requires local access, it could be leveraged as part of a more complex attack chain, for example, after initial access is gained through a separate vulnerability or social engineering.

## Recommendation

*   Monitor for the execution of Snes9K followed by unusual process creation, using the `process_creation` Sigma rule provided below.
*   Monitor for applications writing to Snes9K configuration files followed by the execution of Snes9K, using the `file_event` and `process_creation` Sigma rules provided below.
*   Consider removing the vulnerable software from systems or restricting access to it until a patched version is available.
