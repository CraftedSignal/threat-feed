---
title: Entra ID Microsoft Authentication Broker DRS Sign-In from Suspicious ASN
slug: 2026-05-entra-id-auth-broker-drs-suspicious-asn
description: Detects Microsoft Entra ID sign-in activity where the Microsoft Authentication Broker requests the Device Registration Service from a suspicious ASN, indicating potential OAuth phishing or adversary-in-the-middle device registration.
date: "2026-05-29T10:36:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - identity
  - azure
  - entra_id
  - sign-in_logs
  - threat_detection
  - initial_access
  - persistence
  - oauth
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/
rules:
  - title: Entra ID Microsoft Authentication Broker DRS Sign-In from Suspicious ASN
    description: Detects Microsoft Entra ID sign-in activity where the Microsoft Authentication Broker requests the Device Registration Service from a source ASN associated with VPN, residential proxy, or hosting egress.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1098.005
      - T1550.001
      - T1566.002
    data_sources:
      - network_connection
      - azure
  - title: Entra ID Sign-in from Suspicious ASN Organization
    description: Detects Microsoft Entra ID sign-in activity from ASNs whose organization names suggest VPN, proxy, or hosting services.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
      - persistence
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

This detection identifies suspicious Microsoft Entra ID sign-in activity where the Microsoft Authentication Broker requests the Device Registration Service (DRS) from autonomous system numbers (ASNs) associated with VPNs, residential proxies, or hosting egress. This activity is often observed in OAuth phishing and adversary-in-the-middle (AitM) device registration attacks. Successful exploitation leads to unauthorized device joins or primary refresh token (PRT) acquisition, enabling persistent access to the victim's Entra ID resources. The detection logic focuses on identifying broker-to-DRS sign-ins originating from suspicious ASNs, a technique used by threat actors to stage device registration from attacker-controlled infrastructure after a user has completed the initial authentication flow.

## Attack Chain

1.  The attacker crafts a phishing email containing a malicious link or attachment.
2.  The victim clicks the link and is redirected to a fake login page impersonating Microsoft Entra ID.
3.  The victim enters their credentials on the fake login page, which are then stolen by the attacker.
4.  The attacker uses the stolen credentials to initiate a Microsoft Authentication Broker request to the Device Registration Service (DRS) from a VPN, proxy, or hosting ASN (e.g. 399629, 14061, 136787).
5.  The Microsoft Authentication Broker attempts to register a device with the Entra ID tenant.
6.  The Device Registration Service processes the request, potentially granting the attacker control over the registered device.
7.  The attacker obtains a Primary Refresh Token (PRT) for the compromised account.
8.  The attacker uses the PRT to maintain persistent access to the victim's Entra ID resources, bypassing multi-factor authentication.

## Impact

Compromised Entra ID accounts can lead to significant data breaches, unauthorized access to sensitive information, and disruption of business operations. Attackers can use stolen credentials and PRTs to gain persistent access to cloud resources, impersonate legitimate users, and move laterally within the organization's network. Successful device registration enables attackers to bypass security controls and maintain long-term access, making detection and remediation challenging. The use of VPNs and proxies obfuscates the attacker's true location, hindering investigations and attribution.

## Recommendation

*   Deploy the Sigma rule `Entra ID Microsoft Authentication Broker DRS Sign-In from Suspicious ASN` to your SIEM and tune for your environment to detect malicious sign-in activity.
*   Investigate any sign-ins matching the rule criteria by reviewing `azure.signinlogs.properties.user_principal_name`, `azure.signinlogs.properties.app_display_name`, and `source.as.organization.name`.
*   Compare ASN organizations against approved VPN, MDM, and automation egress in your environment as noted in the rule's `false_positives` section.
*   Review Entra ID audit logs for device registration activity around the same timestamp and correlate `azure.signinlogs.properties.session_id` with other sign-ins for the same user as described in the rule's `note` section.
*   Consider implementing Conditional Access policies for the Microsoft Authentication Broker and device registration requirements as described in the rule's `note` section.
