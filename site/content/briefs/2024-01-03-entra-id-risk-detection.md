---
title: Entra ID Protection - Sign-in Risk Detection
slug: 2024-01-03-entra-id-risk-detection
description: This brief covers detection of sign-in risk events identified by Microsoft Entra ID Protection, including anonymized IP addresses, unlikely travel, and password spray attacks, which can indicate compromised accounts or malicious activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - entra-id
  - identity-protection
  - sign-in-risk
  - initial-access
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - https://github.com/dirkjanm/ROADtools
  - https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/
  - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#risk-types-and-detection
  - https://www.microsoft.com/en-us/security/blog/2025/05/27/new-russia-affiliated-actor-void-blizzard-targets-critical-sectors-for-espionage/
rules:
  - title: Entra ID Protection - High Risk Sign-in Detected
    description: Detects high-risk sign-in events reported by Entra ID Protection.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - authentication
      - azure
  - title: Entra ID Protection - Sign-in from Anonymized IP Address
    description: Detects sign-ins flagged by Entra ID Protection originating from anonymizing proxies.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - initial_access
    techniques:
      - T1071
    data_sources:
      - authentication
      - azure
  - title: Entra ID Protection - Unlikely Travel Sign-in
    description: Detects sign-ins flagged by Entra ID Protection as Unlikely Travel.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1071
    data_sources:
      - authentication
      - azure
rules_count: 3
---

Microsoft Entra ID Protection is a service that detects anomalies and risks associated with user sign-ins. This includes detecting sign-ins from anonymized IP addresses (VPN, Tor), identifying unlikely travel patterns, and detecting password spray attacks. This analysis is based on the "Entra ID Protection - Risk Detection - Sign-in Risk" rule from Elastic. The rule leverages Microsoft Entra ID Protection logs to identify potentially malicious or compromised accounts, allowing security teams to quickly triage and respond to these threats. The detections are designed to cover a wide array of initial access techniques targeting cloud environments. The references highlight real-world campaigns targeting Microsoft 365 and Entra ID environments, showing the importance of monitoring these risks.

## Attack Chain

1. **Initial Access:** An attacker attempts to gain initial access using techniques like password spraying (T1110.003) or exploiting valid accounts (T1078).
2. **Password Spraying:** The attacker uses a list of common passwords against multiple accounts (T1110.003). Entra ID Protection detects the unusual pattern of failed login attempts across multiple accounts.
3. **Anonymized IP Address:** The attacker uses VPNs or Tor to mask their location (T1071). Entra ID Protection flags the sign-in due to the use of an anonymizing proxy.
4. **Unlikely Travel:** The attacker logs in from a location drastically different from the user's typical locations within a short timeframe. This is flagged by Entra ID Protection as unlikely travel (T1071).
5. **Risk Detection:** Entra ID Protection detects the sign-in risk event and generates a "User Risk Detection" log.
6. **Account Compromise:** If successful, the attacker gains access to the target account.
7. **Lateral Movement/Privilege Escalation (Potential):** The attacker may attempt to move laterally within the cloud environment or escalate privileges to gain further access.
8. **Data Exfiltration/Impact (Potential):** The attacker may attempt to exfiltrate sensitive data or cause damage to the organization's resources.

## Impact

A successful attack following these steps can lead to account compromise, data breaches, and unauthorized access to sensitive resources. Organizations may face financial losses, reputational damage, and legal consequences. The risk detections indicate a potential compromise that requires immediate investigation. By identifying and responding to these sign-in risks, organizations can prevent further damage.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM to detect Entra ID Protection sign-in risk events and tune them for your environment.
*   Enable Microsoft Entra ID Protection logs and stream them into your security information and event management (SIEM) system, as required by the rule setup.
*   Implement sign-in risk policies in Entra ID Protection to automatically respond to risk events, such as requiring multi-factor authentication or blocking sign-ins from risky locations, as suggested in the rule's "Response and Remediation" section.
*   Review authentication material such as primary refresh tokens (PRTs) or OAuth tokens to ensure they have not been compromised as mentioned in the rule's "Response and Remediation" section.
