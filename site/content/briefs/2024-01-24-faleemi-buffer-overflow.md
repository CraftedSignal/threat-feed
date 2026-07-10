---
title: Faleemi Desktop Software 1.8 Local Buffer Overflow Vulnerability
slug: 2024-01-24-faleemi-buffer-overflow
description: Faleemi Desktop Software 1.8 is vulnerable to a local buffer overflow in the System Setup dialog, allowing attackers to bypass DEP protections and execute arbitrary code through a crafted payload in the Save Path field.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer-overflow
  - dep-bypass
  - faleemi
  - cve-2019-25691
vendors:
  - Faleemi
products:
  - Faleemi Desktop Software
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2019-25691
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25691
  - https://www.exploit-db.com/exploits/46269
  - https://www.faleemi.com/
  - https://www.vulncheck.com/advisories/faleemi-desktop-software-local-buffer-overflow-seh-dep-bypass
rules:
  - title: Detect Faleemi Desktop Software Suspicious Child Process
    description: Detects suspicious child processes spawned by Faleemi Desktop Software, potentially indicating exploitation.
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
  - title: Detect Faleemi Desktop Software Registry Modification
    description: Detects registry modifications by Faleemi Desktop Software which may indicate malicious activity post exploitation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Faleemi Desktop Software version 1.8 is susceptible to a critical local buffer overflow vulnerability (CVE-2019-25691) within the System Setup dialog. This flaw allows an attacker with local access to the system to inject a malicious payload into the "Save Path for Snapshot and Record file" field. By exploiting this buffer overflow, attackers can bypass Data Execution Prevention (DEP) and execute arbitrary code on the affected system. This is achieved through Structured Exception Handling (SEH) exploitation, enabling the use of Return-Oriented Programming (ROP) chain gadgets to gain control and execute malicious code. The vulnerability poses a significant risk to systems running the vulnerable software.

## Attack Chain

1.  Attacker gains local access to a system with Faleemi Desktop Software 1.8 installed.
2.  Attacker opens the Faleemi Desktop Software application.
3.  Attacker navigates to the "System Setup" dialog within the application's settings.
4.  Attacker locates the "Save Path for Snapshot and Record file" field in the settings.
5.  Attacker injects a specially crafted payload designed to trigger a buffer overflow into the "Save Path" field. The payload includes shellcode and ROP gadgets.
6.  The application attempts to save the provided path, triggering the buffer overflow.
7.  The injected payload overwrites memory, including the Structured Exception Handler (SEH) record.
8.  The overwritten SEH record redirects execution to the attacker's controlled ROP chain, enabling arbitrary code execution on the system.

## Impact

Successful exploitation of this buffer overflow vulnerability (CVE-2019-25691) allows an attacker to execute arbitrary code with the privileges of the user running Faleemi Desktop Software 1.8. This could lead to complete system compromise, including data theft, installation of malware, or further lateral movement within the network. Given the nature of the vulnerability, any system running the affected software is at risk. The CVSS v3.1 score of 8.4 indicates a high severity.

## Recommendation

*   Apply any available patches or updates provided by Faleemi to address CVE-2019-25691.
*   Monitor process creation events for spawned processes originating from Faleemi Desktop Software using the provided Sigma rule to detect potential exploitation attempts.
*   Implement application control policies to restrict the execution of unsigned or untrusted binaries within the Faleemi Desktop Software directory.
