---
title: Suspicious Remote Installation via MsiExec
slug: 2024-01-msiexec-remote-install
description: This rule detects the execution of msiexec.exe to install a file from a remote server, a technique adversaries abuse for initial access and malware delivery by leveraging Windows Installers and initiating network activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - msiexec
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/007/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_msiexec_remote_payload.toml
rules:
  - title: Detect Remote MSI Install via MsiExec
    description: Detects msiexec.exe being used to install a package from a remote URL.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
  - title: Detect MsiExec with Suspicious Parent Processes
    description: Detects MsiExec execution initiated by unusual parent processes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may abuse the Windows Installer service (msiexec.exe) to perform malicious actions such as installing malware from remote locations. This involves using msiexec.exe with command-line arguments that specify a remote URL as the source for an installation package, potentially bypassing traditional security controls. This activity is often observed in the context of initial access or defense evasion, where the attacker attempts to execute arbitrary code under the guise of a legitimate installation process. The detection focuses on identifying msiexec.exe processes that initiate network connections to download and execute MSI packages, particularly when combined with flags that suppress user interaction, such as `/qn` or `/quiet`. The described technique is used to execute malicious payloads by disguising them as legitimate installations.

## Attack Chain

1. An attacker gains initial access to the system through a vulnerability or social engineering.
2. The attacker executes a command-line interpreter (cmd.exe, powershell.exe) or script host (wscript.exe, mshta.exe) to initiate the malicious installation.
3. MsiExec.exe is invoked with arguments specifying a remote URL (e.g., `http://evil.com/malware.msi`) as the installation source using the `/i` or `-i` parameter.
4. The `/qn`, `-qn`, `/q`, or `/quiet` flags are used to suppress user interaction during the installation process, making it stealthier.
5. MsiExec.exe downloads the MSI package from the remote server.
6. MsiExec.exe executes the downloaded MSI package, which may contain malicious payloads, scripts, or executables.
7. The malicious payload performs actions such as installing malware, establishing persistence, or exfiltrating data.
8. The attacker achieves their final objective, which may include data theft, system compromise, or establishing a foothold for further attacks.

## Impact

Successful exploitation allows attackers to execute arbitrary code on the targeted system, leading to malware installation, data compromise, or complete system takeover. The use of a legitimate system tool like MsiExec.exe makes the attack harder to detect and attribute. Observed damage can include data exfiltration, ransomware deployment, or the establishment of persistent backdoors. The impact can range from individual workstation compromise to widespread network infection, depending on the attacker's objectives and capabilities.

## Recommendation

*   Enable Sysmon process-creation logging to detect MsiExec execution with command-line arguments indicative of remote installations, activating the associated Sigma rules.
*   Monitor Windows Security Event Logs for events related to MsiExec.exe process creations.
*   Implement network monitoring to detect connections to unusual or malicious domains and IP addresses associated with MSI downloads.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
