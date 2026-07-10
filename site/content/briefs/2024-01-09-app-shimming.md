---
title: Potential Application Shimming via Sdbinst
slug: 2024-01-09-app-shimming
description: This brief covers the abuse of application shimming in Windows via `sdbinst.exe` to achieve persistence and privilege escalation by executing arbitrary code within legitimate processes.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - application-shimming
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546
    technique_name: Event Triggered Execution
references:
  - https://attack.mitre.org/techniques/T1546/
  - https://attack.mitre.org/techniques/T1546/011/
rules:
  - title: Potential Application Shimming via Sdbinst
    description: Detects suspicious invocations of sdbinst.exe used to create application shims for persistence and privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1546.011
    data_sources:
      - process_creation
      - windows
  - title: Application Shimming - File Creation
    description: Detects the creation of .sdb files, potentially indicating application shimming activity.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1546.011
    data_sources:
      - file_event
      - windows
  - title: Application Shimming - Registry Modification
    description: Detects modifications to the AppCompatFlags registry key, which can indicate application shimming activity.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1546.011
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

Application shimming is a Windows mechanism intended for backward compatibility, allowing older software to run on newer operating systems. Attackers abuse this functionality by using the `sdbinst.exe` utility to create application compatibility databases (SDB files) that inject malicious code into legitimate processes. This allows for persistent code execution and potential privilege escalation. This technique has been observed across various Windows environments, with detection focusing on unusual command-line arguments used with `sdbinst.exe`. The rule `Potential Application Shimming via Sdbinst` detects suspicious invocations of `sdbinst.exe` by filtering out benign arguments, flagging potential misuse for further investigation and remediation, without relying on specific threat actor attribution.

## Attack Chain

1.  Attacker gains initial access to the system (e.g., through phishing or exploiting a vulnerability).
2.  The attacker executes `sdbinst.exe` with malicious command-line arguments to install a custom application compatibility database (.sdb file).
3.  The .sdb file is crafted to modify the behavior of a legitimate application.
4.  When the targeted application is executed, the shimming mechanism loads the malicious .sdb file.
5.  The malicious code within the .sdb file is injected into the application's process.
6.  The injected code executes, allowing the attacker to perform actions such as installing malware, establishing persistence, or escalating privileges.
7.  The attacker maintains persistence by ensuring the shimming mechanism continues to load the malicious .sdb file on subsequent application launches.

## Impact

Successful exploitation of application shimming allows attackers to gain persistent access to a system and execute arbitrary code with the privileges of the targeted application. This can lead to data theft, system compromise, and further lateral movement within the network. While a precise victim count isn't specified in the source, the technique's stealthy nature makes it highly effective for long-term compromise. The impact ranges from minor data breaches to complete system takeover depending on the permissions of the shimed application.

## Recommendation

*   Deploy the Sigma rule "Potential Application Shimming via Sdbinst" to your SIEM to detect suspicious `sdbinst.exe` executions (see the `rules` section).
*   Monitor process execution logs for `sdbinst.exe` invocations and investigate any instances where the command-line arguments do not include `-m`, `-bg`, or `-mm` (see the `rules` section and the rule description).
*   Implement file integrity monitoring for application compatibility databases (.sdb files) to detect unauthorized modifications or additions (reference file_event category in the Sigma rules).
*   Review and audit existing application shims for any signs of compromise or unauthorized modifications (reference registry_set category in the Sigma rules, targeting the `AppCompatFlags` registry key).
