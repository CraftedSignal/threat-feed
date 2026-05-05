---
title: Malicious Use of Microsoft Intune Device Management Configuration Policies
slug: 2024-01-intune-config-policy
description: Attackers can abuse Microsoft Intune device management configuration policies, typically used for legitimate remote device management, to disable defenses and evade detection on managed devices.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - azure
  - intune
  - device_management
  - policy
  - defense_evasion
vendors:
  - Microsoft
products:
  - Intune
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1072
    technique_name: Software Deployment Tools
references:
  - https://posts.specterops.io/death-from-above-lateral-movement-from-azure-to-on-prem-ad-d18cb3959d4d
  - https://securityintelligence.com/x-force/detecting-intune-lateral-movement/
  - https://posts.specterops.io/maestro-9ed71d38d546
rules:
  - title: Detect Intune Device Configuration Policy Creation
    description: Detects the creation of new device management configuration policies in Microsoft Intune, which could be used for malicious purposes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - cloud
      - azure
      - monitor
  - title: Detect Intune Device Configuration Policy Update
    description: Detects the update of device management configuration policies in Microsoft Intune, which could be used for malicious purposes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - cloud
      - azure
      - monitor
rules_count: 2
---

Microsoft Intune device management configuration policies provide administrators with the ability to remotely manage settings on Intune-managed devices. However, attackers can misuse this capability to disable security defenses and evade detection mechanisms. The creation or modification of device management configuration policies should be monitored closely for signs of malicious activity. This includes policies that weaken security configurations, such as disabling endpoint detection and response (EDR) or modifying firewall rules. Such actions can lead to successful lateral movement from Azure to on-premise Active Directory, as well as disabling logging/auditing capabilities.

## Attack Chain

1. An attacker gains initial access to an Azure tenant, potentially through compromised credentials or exploitation of a vulnerability.
2. The attacker authenticates to the Azure portal and elevates privileges to gain sufficient permissions to manage Intune.
3. The attacker creates a new Device Management Configuration Policy within Intune.
4. The malicious policy targets specific devices or groups of devices managed by Intune.
5. The policy modifies security settings, such as disabling Windows Defender, turning off firewall rules, or disabling security auditing.
6. The targeted devices receive the policy update and apply the changes, weakening their security posture.
7. The attacker leverages the compromised devices for lateral movement within the network, potentially targeting on-premise Active Directory.
8. The attacker achieves their final objective, such as data exfiltration, ransomware deployment, or long-term persistence.

## Impact

Successful exploitation can lead to widespread compromise of Intune-managed devices, weakening their security posture and enabling further malicious activities. Attackers could disable critical security controls, allowing them to move laterally within the network, compromise sensitive data, and potentially impact on-premises Active Directory environments. The references indicate this technique has been observed in attacks involving lateral movement from Azure to on-prem AD.

## Recommendation

*   Enable Azure Monitor Activity logging for Intune and ingest logs into your SIEM (reference: data_source).
*   Deploy the Sigma rule `Detect Intune Device Configuration Policy Creation` to detect the creation of new device management configuration policies. Tune the rule based on baselining to reduce false positives (reference: rules).
*   Investigate any new device management configuration policies, particularly those that disable security features or modify critical system settings (reference: rules).
*   Monitor for lateral movement attempts originating from Intune-managed devices, especially after new policies have been deployed (reference: references).
*   Implement multi-factor authentication (MFA) for all Azure accounts, especially those with administrative privileges, to prevent initial access (general security best practice).
*   Review Intune role-based access control (RBAC) to ensure least privilege and prevent unauthorized policy modifications (general security best practice).
