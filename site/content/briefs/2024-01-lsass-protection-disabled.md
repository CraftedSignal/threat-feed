---
title: Disabling LSA Protection via Registry Modification
slug: 2024-01-lsass-protection-disabled
description: Attackers may disable LSA protection by modifying the RunAsPPL registry value in order to access LSASS memory and dump credentials, potentially leading to credential compromise and further lateral movement.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - credential-access
  - windows
  - registry-modification
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
  - https://attack.mitre.org/techniques/T1112/
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/001/
  - https://attack.mitre.org/techniques/T1003/
  - https://attack.mitre.org/techniques/T1003/001/
rules:
  - title: Disabling Lsa Protection via Registry Modification
    description: Detects attempts to disable LSA protection by modifying the RunAsPPL registry value. Attackers may disable Lsa protection to access Lsass memory.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1003
      - T1003.001
      - T1112
      - T1562
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Process Modifying RunAsPPL Registry
    description: Detects suspicious processes modifying the RunAsPPL registry value which controls LSA protection.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1003
      - T1003.001
      - T1112
      - T1562
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Local Security Authority (LSA) protection prevents unauthorized processes from reading LSA memory or injecting code, adding security to credentials stored and managed by LSA. Attackers may disable this protection by modifying the `RunAsPPL` registry value, then restarting the system to enable access to LSASS credentials. This allows adversaries to dump credentials and move laterally. This activity is detected by monitoring for changes to the `RunAsPPL` registry key, excluding legitimate processes like `SecurityHealthService.exe` which may also modify the registry as part of normal system operation. The absence of LSA protection exposes sensitive credentials, making it a critical security risk.

## Attack Chain

1. An attacker gains initial access to the target system, often through phishing or exploiting a software vulnerability.
2. The attacker elevates privileges to administrator level using exploits or stolen credentials.
3. The attacker modifies the `RunAsPPL` registry value located at `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` to disable LSA protection. This is often achieved using tools like `reg.exe` or PowerShell's `Set-ItemProperty`.
4. The attacker may use a script or command-line execution to ensure the registry change persists after a reboot.
5. The attacker restarts the compromised system for the `RunAsPPL` registry modification to take effect.
6. After the reboot, the attacker leverages credential dumping tools like `Mimikatz` or custom scripts to extract credentials from the now unprotected LSASS process memory.
7. The attacker uses the stolen credentials to move laterally within the network, accessing additional systems and data.
8. The attacker achieves their final objective, such as data exfiltration, ransomware deployment, or long-term persistence.

## Impact

A successful attack can compromise sensitive credentials stored in LSASS memory, potentially leading to a wide range of security breaches. Depending on the compromised account's access level, this could lead to lateral movement, data exfiltration, or system-wide compromise. Organizations in all sectors are at risk, with financial institutions and government entities being particularly attractive targets. Disabling LSA protection makes credential theft significantly easier, increasing the likelihood of a successful attack.

## Recommendation

*   Monitor registry modifications to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` using the Sigma rule "Disabling Lsa Protection via Registry Modification" to detect unauthorized attempts to disable LSA protection.
*   Enable Sysmon registry event logging to capture the necessary registry modification events to activate the Sigma rules.
*   Investigate any detected modifications to the `RunAsPPL` registry value, prioritizing changes made by unexpected processes, as highlighted in the rule's description.
*   Regularly review and validate legitimate exceptions to the Sigma rule, such as authorized third-party applications documented in the false positive analysis.
*   Implement the response and remediation steps outlined in the rule's "note" section, including host isolation, malware scanning, and credential resets.
