---
title: Windows MSI Rollback Script Deletion by Non-Msiexec Process
slug: 2024-01-msi-rollback-delete
description: Detection of a rollback script (.rbs) file deletion under C:\Config.Msi by a non-msiexec.exe process, indicating a potential MSI rollback privilege escalation attack.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - rollback
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
cves:
  - id: CVE-2024-44193
    cvss: 7.8
    epss: 0.0322
references:
  - https://github.com/mbog14/CVE-2024-44193
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_msi_rollback_script_deleted_by_non_msiexec_process.yml
rules:
  - title: Detect MSI Rollback Script Deletion
    description: Detects the deletion of a .rbs file under C:\Config.Msi by a process other than msiexec.exe, indicating potential privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1218.007
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Process Deleting MSI Rollback Script
    description: Detects a non-msiexec process deleting an MSI rollback script using a suspicious path, potentially indicating privilege escalation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1218.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief focuses on the detection of a specific technique used in privilege escalation attacks on Windows systems. An attacker attempts to delete a rollback script (.rbs) file located in the `C:\Config.Msi` directory using a process other than `msiexec.exe`. This is a critical step in exploiting the CVE-2024-44193 vulnerability, which allows an attacker to manipulate the Windows Installer service to execute arbitrary code with SYSTEM privileges. The `C:\Config.Msi` directory is normally protected with a strong DACL to prevent tampering, but if an attacker can bypass these protections and delete the rollback script, they can gain SYSTEM-level code execution during a rollback operation. This detection is relevant for organizations using Windows operating systems and relies on monitoring file deletion events.

## Attack Chain

1. An attacker gains initial access to the system, potentially through phishing or exploiting another vulnerability.
2. The attacker identifies a vulnerable MSI installation process or creates their own malicious MSI package.
3. The attacker triggers an MSI installation that creates a rollback script (.rbs) file in the `C:\Config.Msi` directory.
4. The attacker attempts to delete the .rbs file using a non-`msiexec.exe` process, such as `cmd.exe` or `powershell.exe`, bypassing standard installation procedures.
5. If the deletion is successful, the attacker triggers a rollback of the MSI installation.
6. During the rollback, the Windows Installer service attempts to execute the now-missing rollback script.
7. The attacker leverages the missing rollback script to inject and execute arbitrary code with SYSTEM privileges.
8. The attacker achieves privilege escalation, gaining SYSTEM-level control over the compromised system.

## Impact

A successful MSI rollback privilege escalation attack can lead to complete system compromise. An attacker gaining SYSTEM privileges can install malware, steal sensitive data, create new administrative accounts, or disrupt critical services. Given that MSI installers are commonly used to deploy software across Windows environments, this vulnerability has a broad impact across various sectors. If left undetected, this attack can lead to widespread damage, significant data breaches, and long-term operational disruptions.

## Recommendation

*   Enable Sysmon EventID 23 (File Delete) logging to capture the necessary file deletion events in `C:\Config.Msi`.
*   Deploy the Sigma rule `Detect MSI Rollback Script Deletion` to identify unauthorized deletions of .rbs files, and tune for your environment.
*   Investigate any alerts triggered by the Sigma rule, prioritizing those where the deleting process is unusual or untrusted.
*   Review and harden the DACLs on the `C:\Config.Msi` directory to prevent unauthorized file deletions.
*   Monitor for exploitation of CVE-2024-44193 as referenced in the references section, and apply appropriate patches if available from Microsoft.
