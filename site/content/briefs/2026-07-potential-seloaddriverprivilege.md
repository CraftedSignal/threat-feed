---
title: Potential Privileged System Service Operation - SeLoadDriverPrivilege
slug: 2026-07-potential-seloaddriverprivilege
description: This brief details the detection of `SeLoadDriverPrivilege` usage on Windows systems, a critical privilege enabling attackers to load malicious kernel drivers for advanced defense evasion and privilege escalation, leading to full system compromise.
date: "2026-07-03T14:14:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - defense-evasion
  - privilege-escalation
  - detection
vendors:
  - Microsoft
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: This privilege is required to load or unload a device driver. With this privilege, the user can dynamically load and unload device drivers or other code in to kernel mode. If you exclude privileged users/admins and processes, which are allowed to do so, you are maybe left with bad programs trying to load malicious kernel drivers.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: With this privilege, the user can dynamically load and unload device drivers or other code in to kernel mode. If you exclude privileged users/admins and processes, which are allowed to do so, you are maybe left with bad programs trying to load malicious kernel drivers.
    confidence_band: high
references:
  - https://web.archive.org/web/20230331181619/https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4673
rules:
  - title: Potential Privileged System Service Operation - SeLoadDriverPrivilege
    description: Detects the usage of the 'SeLoadDriverPrivilege' which allows dynamic loading/unloading of device drivers, a capability often abused for kernel-mode access, defense evasion, and privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1543.003
      - T1547.006
    data_sources:
      - windows
      - security
rules_count: 1
---

This brief focuses on the detection of the `SeLoadDriverPrivilege` on Windows operating systems, a potent capability that, when abused, allows users to dynamically load and unload device drivers, granting kernel-mode access. This privilege is frequently leveraged by malicious actors for defense evasion, bypassing security controls like Sysmon and other endpoint detection and response (EDR) solutions, as highlighted by tools such as "Ghost-In-The-Logs." Although this privilege is necessary for legitimate system operations and tools like Sysinternals, its use by unauthorized processes or users can indicate a critical security breach. Detecting its illegitimate invocation is crucial for identifying attempts to establish persistence, achieve privilege escalation, or perform advanced evasive maneuvers within an environment. The associated detection rule aims to flag suspicious instances by filtering out common benign activities.

## Attack Chain

The provided source describes a detection mechanism for a specific privilege usage rather than a detailed attack chain for a complete compromise. The core malicious activity centers around the abuse of the `SeLoadDriverPrivilege`.

1.  **Initial Access** (Not detailed in source, assumed prerequisite): An attacker gains a foothold on a Windows system, potentially through phishing or exploiting a vulnerability.
2.  **Privilege Escalation Opportunity**: The attacker identifies an opportunity to leverage a user account or process with `SeLoadDriverPrivilege`.
3.  **Malicious Driver Creation/Deployment**: The attacker prepares a malicious kernel driver designed for defense evasion, privilege escalation, or persistence.
4.  **Driver Loading Attempt**: The attacker attempts to load the malicious driver using the `SeLoadDriverPrivilege`. This action triggers Windows Security Event ID 4673.
5.  **Kernel-Mode Access Gained**: If successful, the malicious driver operates in kernel mode, granting the attacker high-level control over the system.
6.  **Defense Evasion/System Manipulation**: From kernel mode, the attacker can disable or tamper with security products (e.g., EDR, antivirus), modify system logs (e.g., "Ghost-In-The-Logs" techniques), create persistent backdoors, or perform other highly privileged actions.
7.  **Impact (e.g., Data Exfiltration, System Control)**: The kernel-mode access facilitates the attacker's ultimate objectives, such as exfiltrating sensitive data, deploying ransomware, or maintaining long-term control of the compromised system.

## Impact

The successful exploitation of the `SeLoadDriverPrivilege` can lead to severe consequences, as it grants attackers kernel-mode access to a compromised Windows system. This level of access enables comprehensive defense evasion, allowing malicious actors to disable or bypass security controls, tamper with system logs (as demonstrated by tools like "Ghost-In-The-Logs"), and operate with stealth. Ultimately, this can lead to full system compromise, including privilege escalation to SYSTEM, installation of persistent backdoors, data exfiltration, or the deployment of ransomware. While specific victim counts or targeted sectors are not detailed, any organization relying on Windows infrastructure is susceptible to attacks leveraging this privilege for critical system compromise.

## Recommendation

*   Deploy the Sigma rule `Potential Privileged System Service Operation - SeLoadDriverPrivilege` provided in this brief to your SIEM and tune for your environment.
*   Ensure Windows Security Event ID 4673 logging is enabled across all relevant endpoints to capture `SeLoadDriverPrivilege` usage, supporting the rule.
*   Develop and maintain a whitelist of legitimate processes and users authorized to utilize `SeLoadDriverPrivilege` by refining the filters outlined in the `Potential Privileged System Service Operation - SeLoadDriverPrivilege` Sigma rule (e.g., `filter_main_exact`, `filter_optional_others`).
*   Investigate any alerts generated by the `Potential Privileged System Service Operation - SeLoadDriverPrivilege` rule that do not match your established whitelist for potential malicious driver loading activity.
