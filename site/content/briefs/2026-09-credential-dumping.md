---
title: Credential Access via Windows Credential Manager PowerShell Scripts
slug: 2026-09-credential-dumping
description: Adversaries leverage PowerShell scripts to programmatically access and extract stored credentials from the Windows Credential Manager vault.
date: "2026-09-03T13:38:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - powershell
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: Adversaries may search for common password storage locations to obtain user credentials.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_dump_password_windows_credential_manager.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1555/T1555.md
rules:
  - title: Detect Credential Dumping from Windows Credential Manager via PowerShell
    description: Detects the use of PowerShell to access the Windows Credential Manager, typically used by attackers to dump stored credentials.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
    techniques:
      - T1555
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to the SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides actionable pattern for detection.
  hunt_leads:
    - lead: Search for 4104 logs containing PasswordVault or CSharpCodeProvider strings.
      technique_id: T1555
      data_needed:
        - PowerShell script block logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Pattern is characteristic of credential dumping.
---

Adversaries frequently target the Windows Credential Manager to perform credential access, as this utility stores sensitive user passwords, service account credentials, and web application secrets. Attackers utilize PowerShell scripts to interface with the Windows.Security.Credentials.PasswordVault API or dynamically compile code to bypass standard monitoring. By invoking these methods, unauthorized actors can enumerate and decrypt secrets stored within the vault. This activity is a common post-exploitation technique used to facilitate lateral movement or privilege escalation within an environment. Defenders must monitor PowerShell Script Block Logging (Event ID 4104) to identify the execution of these specific API calls and helper classes used by offensive tools to dump credentials.

## Attack Chain

1. Attacker gains initial access or code execution on the target Windows system.
2. Attacker prepares a PowerShell script intended to interact with the Windows Credential Manager.
3. Script uses New-Object to instantiate the Windows.Security.Credentials.PasswordVault class.
4. Script may utilize Microsoft.CSharp.CSharpCodeProvider to compile arbitrary code in memory to interact with system APIs.
5. Script invokes methods like Get-PasswordVaultCredentials or Get-CredManCreds to retrieve stored data.
6. The retrieved credentials are serialized or stored in an ArrayList within the script.
7. Attacker exfiltrates the dumped credentials from the compromised host to attacker-controlled infrastructure.

## Impact

Successful exploitation allows an attacker to obtain cleartext credentials or cached tokens for local and domain users, enabling unauthorized access to internal resources, sensitive applications, and increased privileges within the target organization.

## Recommendation

Deploy the following Sigma rule to detect credential dumping attempts via PowerShell. Ensure PowerShell Script Block Logging is enabled on all endpoints.

* Enable Windows Event ID 4104 (PowerShell Script Block Logging) via Group Policy.
* Monitor for the execution of scripts containing 'Windows.Security.Credentials.PasswordVault' or associated compiler classes.
* Tune alerts to ignore approved administrative maintenance scripts that legitimately interact with the system vault.
