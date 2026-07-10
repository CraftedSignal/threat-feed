---
title: Ghidra Improper Annotation Processing Leads to RCE (CVE-2026-4946)
slug: 2024-01-ghidra-rce
description: Ghidra versions before 12.0.3 improperly process annotation directives from automatically extracted binary data, leading to arbitrary command execution when an analyst interacts with the user interface by clicking on a crafted element.
date: "2024-01-28T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - CVE-2026-4946
  - ghidra
  - rce
vendors:
  - Ghidra
products:
  - Ghidra
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4946
rules:
  - title: Detect Ghidra Spawning Suspicious Processes
    description: Detects Ghidra spawning command interpreters or other suspicious processes, potentially indicating exploitation of CVE-2026-4946.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Ghidra Network Connections to Public IP Ranges
    description: Detects Ghidra making outbound network connections to public IP ranges, potentially indicating exploitation of CVE-2026-4946 and subsequent command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Ghidra spawning unexpected script interpreters
    description: Detects Ghidra spawning processes like cscript.exe, mshta.exe, or wscript.exe, potentially indicating the execution of malicious scripts via CVE-2026-4946.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

CVE-2026-4946 identifies a critical vulnerability affecting Ghidra versions prior to 12.0.3. The vulnerability stems from the improper handling of annotation directives, specifically the `@execute` annotation, embedded within automatically extracted binary data.  Normally, the `@execute` annotation is reserved for trusted user-authored comments. However, due to the flaw, Ghidra parses these annotations even when they originate from auto-analysis processes like CFStrings extraction in Mach-O binaries. Consequently, a malicious actor can craft a binary file containing a seemingly harmless clickable element (text), which, when clicked by an analyst, triggers the execution of arbitrary, attacker-controlled commands on the analyst's machine. The vulnerability allows remote code execution on the Ghidra analyst's workstation.

## Attack Chain

1.  Attacker crafts a malicious binary file containing embedded annotation directives within automatically extracted data (e.g., CFStrings in a Mach-O binary). The directive uses the `@execute` annotation to embed a command.
2.  The analyst loads the crafted binary into a vulnerable version of Ghidra (prior to 12.0.3).
3.  Ghidra's auto-analysis engine processes the binary and extracts the embedded data, including the malicious `@execute` annotation.
4.  Ghidra displays the extracted data in the UI, rendering the malicious annotation as a seemingly benign clickable element.
5.  The analyst, unaware of the malicious intent, clicks on the displayed element within the Ghidra UI.
6.  Upon clicking, Ghidra improperly processes the `@execute` annotation and executes the attacker-controlled command on the analyst's machine.
7.  The attacker achieves arbitrary command execution within the security context of the analyst's Ghidra process.
8.  The attacker pivots from the initial command execution to further compromise the analyst's system (e.g., installing malware, exfiltrating sensitive data).

## Impact

Successful exploitation of CVE-2026-4946 allows attackers to execute arbitrary commands on the system of a Ghidra analyst. This could lead to complete system compromise, data theft, or the installation of persistent backdoors. Given that Ghidra is used by reverse engineers analyzing potentially malicious software, this vulnerability poses a significant risk. The impact is especially severe because analysts often work with sensitive data and privileged accounts, potentially allowing attackers to gain access to highly sensitive information. The number of potential victims is large due to Ghidra's widespread use in security research and software development.

## Recommendation

*   Upgrade Ghidra to version 12.0.3 or later to patch CVE-2026-4946.
*   Implement application control to restrict the execution of unauthorized processes spawned by Ghidra, mitigating the impact of successful exploitation.
*   Monitor process execution events for unusual or unexpected child processes spawned by the Ghidra process using the process_creation Sigma rules provided.
