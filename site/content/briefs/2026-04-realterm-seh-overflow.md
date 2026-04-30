---
title: RealTerm Serial Terminal SEH Buffer Overflow Vulnerability (CVE-2019-25679)
slug: 2026-04-realterm-seh-overflow
description: RealTerm Serial Terminal 2.0.0.70 contains a structured exception handling (SEH) buffer overflow vulnerability allowing local attackers to execute arbitrary code by supplying a malicious payload via the Echo Port tab.
date: "2026-04-05T21:16:46Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2019-25679
  - buffer-overflow
  - seh
  - local-code-execution
  - realterm
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2019-25679
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25679
  - https://realterm.sourceforge.io/
  - https://sourceforge.net/projects/realterm/files/
  - https://www.exploit-db.com/exploits/46441
  - https://www.vulncheck.com/advisories/realterm-serial-terminal-buffer-overflow-seh
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: RealTerm SEH Overflow Attempt
    description: Detects potential SEH overflow attempts in RealTerm by monitoring for Realterm.exe processes being launched with unusually long command-line arguments, which may indicate a buffer overflow payload.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: RealTerm Suspicious Child Process
    description: Detects suspicious child processes spawned by RealTerm, which may indicate successful exploitation leading to code execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

RealTerm Serial Terminal version 2.0.0.70 is vulnerable to a structured exception handling (SEH) buffer overflow in the Echo Port tab. This vulnerability, identified as CVE-2019-25679, allows a local attacker to execute arbitrary code on a vulnerable system. The attack requires the user to be running the RealTerm application. The attacker must craft a malicious payload containing shellcode and a POP POP RET gadget chain and paste it into the Port field within the Echo Port tab. Subsequently, the attacker needs to induce the user to click the "Change" button, triggering the buffer overflow and allowing arbitrary code execution within the context of the RealTerm application. This poses a significant risk, particularly in environments where RealTerm is used for debugging or serial communication.

## Attack Chain

1.  The attacker identifies a vulnerable RealTerm Serial Terminal 2.0.0.70 installation.
2.  The attacker crafts a malicious payload containing shellcode and a POP POP RET gadget chain.
3.  The attacker gains local access to the target system.
4.  The attacker opens the RealTerm application and navigates to the Echo Port tab.
5.  The attacker pastes the malicious payload into the Port field.
6.  The attacker induces the user to click the "Change" button.
7.  The buffer overflow occurs, overwriting the SEH handler.
8.  The POP POP RET gadget chain is executed, redirecting control to the attacker's shellcode, resulting in arbitrary code execution.

## Impact

Successful exploitation of this vulnerability (CVE-2019-25679) allows a local attacker to execute arbitrary code on the affected system. This could lead to complete system compromise, including data theft, installation of malware, or denial of service. Although specific victim counts and targeted sectors are not available, the widespread use of RealTerm in technical environments makes this a potentially significant threat.

## Recommendation

*   Deploy the "RealTerm SEH Overflow Attempt" Sigma rule to detect suspicious process creation following the execution of RealTerm with a long string supplied as an argument.
*   Monitor process creations where the parent process name is Realterm.exe using the "RealTerm Suspicious Child Process" Sigma rule.
*   Although not directly available, consider network monitoring to detect anomalies should the attacker install malware after successful exploitation.
