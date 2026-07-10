---
title: Entra ID Protection Admin Confirmed Compromise
slug: 2024-01-entra-id-compromise
description: An administrator's confirmation of a compromised user or sign-in in Microsoft Entra ID Protection signals a high-confidence account compromise requiring immediate investigation and remediation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - azure
  - entra_id
  - identity_protection
  - compromised_account
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk
  - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
  - https://learn.microsoft.com/en-us/graph/api/resources/riskdetection
rules:
  - title: Entra ID Protection Admin Confirmed Compromise
    description: Detects when an administrator has manually confirmed a user or sign-in as compromised in Microsoft Entra ID Protection.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - azure
      - o365
  - title: Entra ID Protection - High Risk Sign-in Detected
    description: Detects a high-risk sign-in event in Entra ID Protection based on the risk level.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - azure
      - o365
  - title: Entra ID Protection - Medium Risk Sign-in Detected
    description: Detects a medium-risk sign-in event in Entra ID Protection based on the risk level.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - azure
      - o365
rules_count: 3
---

This alert identifies when an administrator has manually confirmed a user or sign-in as compromised within Microsoft Entra ID Protection. This action signifies that the administrator has investigated and validated the risk detection, confirming a definitive account compromise. The event is a high-confidence indicator and requires immediate investigation. The compromise could have originated from various initial access vectors and may lead to lateral movement and data exfiltration. The detection relies on the presence of specific events in the Azure Identity Protection logs. The scope of targeting is all organizations utilizing Entra ID Protection.

## Attack Chain

1. Initial access is achieved through an unknown method (e.g., phishing, credential stuffing, or malware).
2. The attacker successfully authenticates to a user account within the Entra ID environment.
3. Entra ID Protection detects suspicious activity based on configured risk detections.
4. An administrator reviews the risk detection within the Entra ID Protection portal.
5. The administrator confirms the user or sign-in as compromised based on the evidence.
6. The compromised account may be used for lateral movement within the organization's cloud resources.
7. The attacker may attempt to escalate privileges or access sensitive data.
8. The ultimate objective may be data exfiltration, disruption of services, or other malicious activities.

## Impact

A successful compromise of an Entra ID account can lead to significant damage, including unauthorized access to sensitive data, lateral movement within the organization's cloud infrastructure, privilege escalation, and potential data exfiltration. The impact depends on the privileges and access rights of the compromised account, potentially affecting all resources and applications accessible to that user. If successful, an attacker can gain a foothold in the cloud environment, leading to data breaches, financial loss, and reputational damage.

## Recommendation

*   Enable and monitor Microsoft Entra ID Protection logs to detect confirmed compromised accounts (Required Microsoft Entra ID Protection Logs).
*   Deploy the Sigma rule "Entra ID Protection Admin Confirmed Compromise" to your SIEM to detect confirmed compromised accounts and sign-ins. Tune the rule based on your environment's specific configurations (Sigma rule).
*   Upon detection, immediately reset the password and revoke active sessions for the compromised user account as part of your incident response plan (note).
*   Investigate the Azure logs for the affected user account to determine the initial access method and any subsequent malicious activity (azure.identityprotection.properties.*).
