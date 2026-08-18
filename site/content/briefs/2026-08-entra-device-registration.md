---
title: Detection of Unauthorized Device Registration in Microsoft Entra ID
slug: 2026-08-entra-device-registration
description: Adversaries are leveraging unauthorized device registration in Microsoft Entra ID to obtain Primary Refresh Tokens (PRT) and maintain persistent, authenticated access to cloud environments.
date: "2026-08-18T20:47:22Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - identity
  - persistence
  - azure
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries may create and register a new device to obtain a Primary Refresh Token (PRT) and maintain persistent access.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Identifies when a Microsoft Entra ID user signs in from a device that is not typically used by the user, which may indicate potential compromise or unauthorized access attempts.
    confidence_band: high
references:
  - https://pushsecurity.com/blog/consentfix
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review sign-in logs for non-managed device registrations within the last 7 days.
      owner: SOC
      due: 24h
      evidence: New terms logic focuses on user_principal_name and device_id history.
  hunt_leads:
    - lead: Identify users with unusual login locations or unrecognized application IDs combined with new device registrations.
      technique_id: T1098.005
      data_needed:
        - Azure Sign-in logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Adversaries use first-party client IDs to blend in with legitimate traffic.
  mitigation_plan:
    - priority: immediate
      action: Review and harden Conditional Access policies to restrict device registration capabilities.
      owner: IT Operations
      addresses: T1098.005
      evidence: Review the conditional access policies in place to ensure they are sufficient to prevent unauthorized access to sensitive resources.
---

Adversaries are increasingly using unauthorized device registration to maintain long-term access to Microsoft Entra ID environments. By registering a new device to a user account, attackers can obtain a Primary Refresh Token (PRT), effectively bypassing certain session-based controls and maintaining persistence as a valid, albeit unauthorized, user. This technique is particularly effective because it allows attackers to blend in with legitimate traffic by appearing as a registered device within the cloud environment. Attackers often utilize first-party client IDs and legitimate OAuth workflows to perform this registration. Defenders must monitor for sign-in activity originating from non-managed, previously unseen devices, as these often serve as the first indicator of a compromised or manipulated cloud identity. This activity is frequently associated with phishing for authentication codes or broader OAuth workflow exploitation.

## Impact

Successful device registration enables attackers to gain persistent access, facilitate token theft, and perform post-compromise activities like API data exfiltration. This behavior has been observed in campaigns targeting Microsoft 365 environments, where the final objective is the acquisition of persistent cloud sessions that survive password resets or typical session expirations.

## Recommendation

Detection teams should focus on identifying anomalous device associations for user accounts.
- Implement monitoring for sign-in events involving devices not identified as managed, specifically those that are not hybrid-joined.
- Configure alerts for new combinations of user accounts and device IDs, as provided by the new-terms detection logic.
- Review Entra ID sign-in logs for unexpected incoming_token_type values, particularly primaryRefreshToken usage from unknown device_id entries.
- Enforce conditional access policies that restrict device registration to compliant or enrolled hardware.
