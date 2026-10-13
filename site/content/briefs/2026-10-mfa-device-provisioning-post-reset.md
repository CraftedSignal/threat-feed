---
title: Detection of Anomalous MFA Device Provisioning Following Credential Reset
slug: 2026-10-mfa-device-provisioning-post-reset
description: This detection brief identifies potential account takeover attempts by monitoring for the provisioning of a new MFA device within one hour of a Windows password reset event.
date: "2026-10-13T11:39:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - identity-security
  - mfa
  - account-takeover
  - persistence
vendors:
  - Ping Identity
  - Microsoft
products:
  - PingID
  - Active Directory
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: The following analytic identifies the provisioning of a new MFA device shortly after a password reset.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1621
    technique_name: Multi-Factor Authentication Request Generation
    evidence: This behavior is significant as it may indicate a social engineering attack where a threat actor impersonates a valid user.
    confidence_band: high
references:
  - https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/defend-your-users-from-mfa-fatigue-attacks/ba-p/2365677
  - https://www.bleepingcomputer.com/news/security/mfa-fatigue-hackers-new-favorite-tactic-in-high-profile-breaches/
  - https://attack.mitre.org/techniques/T1098/005/
  - https://attack.mitre.org/techniques/T1556/006/
  - https://docs.pingidentity.com/r/en-us/pingoneforenterprise/p14e_subscriptions?tocId=3xhnxjX3VzKNs3SXigWnQA
action_plan:
  priority: elevated
  owners:
    - SOC
    - Identity Team
  immediate_actions:
    - action: Review logs for potential MFA device pairing events occurring within 1 hour of password resets.
      owner: SOC
      due: 24h
      evidence: Analytic identifies the provisioning of a new MFA device shortly after a password reset.
  hunt_leads:
    - lead: Identify users who registered a new MFA device shortly after a password reset event.
      technique_id: T1621
      data_needed:
        - Active Directory Security Event Logs (4723, 4724)
        - PingID Device Pairing Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This behavior is significant as it may indicate a social engineering attack.
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict verification procedures for MFA device registration post-password-reset.
      owner: Identity Team
      addresses: T1556.006
      evidence: Legitimate IT provisioning might cause false positives; define clear policy to reduce noise.
---

This threat brief focuses on detecting account takeover patterns involving Multi-Factor Authentication (MFA) manipulation. Threat actors often employ social engineering techniques to deceive users or helpdesk personnel into performing a password reset. Once the attacker gains control of the account credentials, they move to register a new MFA device under their control to ensure persistent access. 

The activity is identified by correlating Windows Security Event Logs (specifically Event IDs 4723 for password changes and 4724 for password resets) with PingID (PingOne) device pairing logs. The detection logic flags new MFA device provisioning events that occur within 60 minutes of a password change for the same user identity. This window is a high-fidelity indicator of a potential compromise, as legitimate user provisioning workflows rarely follow immediately after an unexpected password reset.

## Attack Chain

1. Attacker performs social engineering against a target or helpdesk to facilitate a password reset.
2. Target identity performs a password reset, generating Event ID 4723 or 4724 in the Active Directory Security logs.
3. Attacker uses the newly acquired or reset credentials to authenticate into the environment.
4. Attacker navigates to the MFA management portal associated with PingID.
5. Attacker initiates the device pairing process for a new, attacker-controlled device (e.g., a rogue smartphone).
6. PingID logs the pairing event indicating that a new device is associated with the compromised user account.
7. Attacker successfully bypasses traditional security measures using the secondary authentication factor on their rogue device.
8. Attacker establishes persistent access and proceeds with objective-oriented activities (exfiltration, lateral movement).

## Impact

Successful exploitation allows an attacker to maintain persistent, authorized access to a target's corporate account, bypassing traditional password-based defenses. This enables unauthorized data access, potential lateral movement within the network, and the ability to operate within the environment under the guise of a legitimate user. The scope is limited to environments utilizing integrated Active Directory and PingID identity architectures.

## Recommendation

Prioritize the implementation of security analytics that correlate identity management logs with authentication events.
- Deploy detection logic to flag instances where PingID 'Device Paired' events occur within 60 minutes of Active Directory password reset events (Event ID 4723 or 4724).
- Enable detailed logging for both Active Directory Domain Controllers and the PingID (PingOne) enterprise environment (via Webhook or Push Subscription).
- Investigate all alerts generated by this logic to distinguish between legitimate IT helpdesk provisioning workflows and potential attacker activity.
- Review the MITRE ATT&CK techniques referenced, specifically T1621 (MFA Request Generation) and T1098.005 (Account Manipulation: MFA Device Registration), to further harden identity infrastructure.
