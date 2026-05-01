---
title: Potential Credential Access via Windows Utilities
slug: 2024-01-potential-credential-access-windows-utilities
description: This rule detects the execution of known Windows utilities often abused to dump LSASS memory or the Active Directory database (NTDS.dit) in preparation for credential access by identifying specific command-line arguments and process names associated with credential dumping activities.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - defense-evasion
  - windows
vendors:
  - Elastic
  - Cisco Systems
  - Microsoft
  - SentinelOne
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://lolbas-project.github.io/
  - https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper
rules:
  - title: Potential Credential Access via Procdump
    description: Detects the execution of procdump.exe with the -ma flag, which is commonly used to dump the LSASS process for credential access.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
  - title: Potential Credential Access via NTDSUtil
    description: Detects the execution of ntdsutil.exe with arguments used to create an IFM (Install From Media) snapshot of the Active Directory database.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.003
    data_sources:
      - process_creation
      - windows
  - title: Potential Credential Access via DiskShadow
    description: Detects the execution of diskshadow.exe with the /s argument to run commands from script.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.003
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This rule identifies the execution of Windows utilities commonly abused to dump LSASS memory or the Active Directory database (NTDS.dit) in preparation for credential access. Attackers often leverage these tools to extract sensitive information, such as user credentials and domain secrets. The utilities of interest include procdump, ProcessDump.exe, WriteMiniDump.exe, RUNDLL32.EXE, RdrLeakDiag.exe, SqlDumper.exe, TTTracer.exe, ntdsutil.exe, and diskshadow.exe. The rule focuses on detecting specific command-line arguments and process names indicative of credential dumping activities. This activity is typically associated with post-exploitation phases, where attackers aim to escalate privileges and move laterally within a network. This detection is crucial for defenders as it can reveal ongoing credential theft attempts, allowing for prompt intervention and mitigation.

## Attack Chain

1.  The attacker gains initial access to a Windows system through various means, such as phishing, exploiting vulnerabilities, or using compromised credentials.
2.  The attacker executes a privileged process, such as `cmd.exe` or `powershell.exe`, to perform reconnaissance and identify potential targets for credential dumping.
3.  The attacker uses a utility like `procdump.exe` with the `-ma` flag to dump the LSASS process memory (`procdump.exe -ma lsass.exe`).
4.  Alternatively, the attacker uses `ntdsutil.exe` to create an IFM (Install From Media) snapshot of the Active Directory database (`ntdsutil.exe "ac i ntds" "ifm" "cr fu c:\\temp" q q`).
5.  The attacker may use `diskshadow.exe` with a script (`/s`) to create shadow copies of the system volume, potentially including the NTDS.dit file.
6.  The attacker stages the dumped credentials or database files in a temporary directory.
7.  The attacker compresses the staged data using archiving tools for easier transfer.
8.  Finally, the attacker exfiltrates the compressed data to an external server for further analysis and credential harvesting.

## Impact

Successful exploitation can lead to widespread credential compromise, allowing attackers to gain unauthorized access to sensitive systems and data. Credential theft can enable lateral movement within the network, privilege escalation, and ultimately, data exfiltration or ransomware deployment. The targeted dumping of LSASS memory exposes user credentials, while the extraction of the Active Directory database can compromise the entire domain. The severity of the impact depends on the scope of the compromise and the sensitivity of the affected data.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM to detect suspicious process execution patterns indicative of credential dumping (Sigma rule: "Potential Credential Access via Procdump").
*   Monitor process creation events for the execution of known credential dumping utilities with suspicious command-line arguments using the provided Sigma rules, enabling process creation logging via Sysmon (Sigma rule: "Potential Credential Access via NTDSUtil").
*   Implement application control policies to restrict the execution of unauthorized or untrusted binaries, especially those associated with credential dumping, referencing the list of tools described in the Overview.
*   Review and harden Active Directory security configurations to prevent unauthorized access to the NTDS.dit file, using Microsoft's security guidance.
*   Regularly audit and monitor systems for suspicious file creation and modification events, particularly those involving potential credential dumps, and ensure proper file integrity monitoring is enabled.
