---
title: Passkey-Themed Social Engineering Targeting Microsoft Cloud Identities
slug: 2026-09-passkey-phishing-cloud
description: Threat actors are using passkey-themed phishing and adversary-in-the-middle attacks to compromise Microsoft cloud accounts, establish persistent access via registered MFA methods, and exfiltrate data via Microsoft Graph API.
date: "2026-09-13T11:00:36Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - UNC6671
tags:
  - phishing
  - cloud-security
  - credential-harvesting
  - mfa-bypass
  - data-exfiltration
vendors:
  - Microsoft
products:
  - SharePoint Online
  - OneDrive for Business
  - Exchange Online
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The attack commonly begins with identity-focused social engineering... urging them to immediately update their passkey... redirected to counterfeit websites.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: The actor enrolled an MFA method under their control, typically by registering a new phone number, authenticator application, or software-based one-time password token.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Conduct high-volume access and download activity aimed at SharePoint Online and OneDrive for Business.
    confidence_band: high
iocs:
  - type: domain
    value: service-nowinc.com
  - type: domain
    value: domainlify.net
  - type: domain
    value: passkeyhelpdesk.com
  - type: domain
    value: secure-passkey.com
  - type: domain
    value: setupmypasskey.com
  - type: domain
    value: add-passkey.com
  - type: domain
    value: integratedsso.com
  - type: domain
    value: oktasession.com
  - type: domain
    value: syncmykey.com
  - type: domain
    value: portalsetuphub.com
ioc_counts:
  domain: 10
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Identity Team
  immediate_actions:
    - action: Review all recent MFA registration events for newly enrolled phone numbers or OTP apps
      owner: Identity Team
      due: 24h
      evidence: The actor enrolled an MFA method under their control.
  hunt_leads:
    - lead: Identify accounts showing abnormal volume of Graph API calls or SharePoint/OneDrive download activity
      technique_id: T1537
      data_needed:
        - Office 365 Audit Logs / Microsoft Entra ID logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Graph activity must be assessed holistically with emphasis on behavioral progression.
  mitigation_plan:
    - priority: immediate
      action: Mandate FIDO2/WebAuthn for all cloud identities
      owner: Identity Team
      addresses: MFA bypass via AitM/phishing
      evidence: This campaign is designed to bypass traditional MFA.
---

Since May 2026, threat actors including UNC6671 (also tracked as Storm-3032 and associated with the Helix extortion brand) have been executing highly targeted cloud identity compromises. The attack utilizes a combination of voice-phishing and passkey-themed lure emails to direct victims to adversary-in-the-middle (AitM) or device-code phishing sites. These sites impersonate legitimate Microsoft sign-in pages to harvest credentials or secure session access without triggering traditional MFA alerts. Once a foothold is established, the attackers bypass existing MFA configurations by enrolling their own phone-based or software-based OTP tokens, transforming a temporary session into a persistent threat. The actors then perform extensive reconnaissance using the Microsoft Graph API, targeting internal users, permissions, and sensitive documents stored in SharePoint Online and OneDrive for Business, often exfiltrating data over multiple days.

## Attack Chain

1. Actor conducts pre-attack research to identify high-value targets and organizational structures using public social networking and professional profiling platforms.
2. Actor initiates voice phishing (vishing) or sends passkey-themed phishing lures via email or Microsoft Teams, impersonating the target's internal IT help desk.
3. Victims are directed to counterfeit websites that mimic the Microsoft sign-in process, facilitating AitM credential harvesting or device-code authentication.
4. Actor captures the session or triggers a successful authentication flow, bypassing initial MFA protections.
5. Actor establishes persistence by registering a new MFA method (phone number, authenticator app, or OTP token) controlled by the attacker.
6. Actor utilizes the compromised identity to perform internal reconnaissance through Microsoft Graph API queries (e.g., enumerating users, groups, and sensitive file paths).
7. Actor exfiltrates high-volume data from SharePoint, OneDrive, and Exchange Online by abusing Graph API calls over an extended period.

## Impact

The campaign results in complete account takeover, leading to unauthorized access to sensitive corporate data and internal resources. Victims experience sustained data exfiltration, with impact ranging from sensitive file exposure to potential business email compromise (BEC). Attackers have demonstrated the ability to maintain persistent access through attacker-enrolled MFA methods, effectively locking out legitimate users and bypassing standard password resets or session terminations.

## Recommendation

Prioritize the monitoring of Microsoft Entra ID and O365 logs for anomalous authentication and API behavior.
- Audit all MFA registration events to identify recently added phone numbers or OTP tokens that lack corporate approval.
- Implement and enforce Conditional Access policies that require phishing-resistant authentication methods, such as FIDO2 security keys, for all users.
- Monitor for anomalous Microsoft Graph API activity patterns, particularly high-volume file enumeration or bulk downloads occurring from unusual IP addresses.
- Block the identified phishing infrastructure domains at the enterprise DNS resolver.
- Conduct organization-wide training focusing on the risks of device-code authentication and passkey-themed social engineering.
