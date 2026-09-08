---
title: Knight Office M365 AiTM Phishing Kit Analysis
slug: 2026-09-knight-office
description: Knight Office is an Adversary-in-the-Middle (AiTM) phishing kit designed to harvest Microsoft 365 session tokens via sophisticated redirects, enabling MFA bypass and rogue device enrollment.
date: "2026-09-08T13:38:15Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.002
    technique_name: Spearphishing Link
    evidence: Threat actor sends a phishing email that lures the victim to a malicious site via an href rather than an attachment.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098.005
    technique_name: Device Registration
    evidence: Threat actor uses an active hijacked session to enroll an unauthorized host into Microsoft Entra ID, completes a rogue device registration, and binds a WHfB key credential to the compromised account.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557.002
    technique_name: Adversary-in-the-Middle
    evidence: While investigating an Adversary-in-the-Middle (AiTM) attack against an organization in August, Huntress came across a control panel for a phishing kit called Knight Office.
    confidence_band: high
references:
  - https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack
iocs:
  - type: ip
    value: 104.37.188.94
ioc_counts:
  ip: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block IP 104.37.188.94 at the network perimeter.
      owner: SOC
      due: 24h
      evidence: Source identified this IP as the Knight Office management console.
  hunt_leads:
    - lead: Search Entra ID logs for unexpected device registration events and new WHfB credentials.
      technique_id: T1098.005
      data_needed:
        - Entra ID Audit Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker performs rogue device registration after token theft.
---

Knight Office is a newly identified Adversary-in-the-Middle (AiTM) phishing kit that facilitates the theft of Microsoft 365 session tokens. First observed in August 2026, the kit utilizes a custom operator console that manages incoming stolen sessions, allowing threat actors to replay these tokens to gain persistent, authenticated access to victim accounts. By intercepting the active session, attackers effectively circumvent password-based security and multi-factor authentication (MFA). 

The infrastructure relies on evasion techniques, including the integration of Cloudflare Turnstile to block automated analysis and the use of legitimate platforms, such as the Monday work management service, to facilitate open redirects. Huntress reports that the kit is being used in active campaigns, with multiple identities already compromised through this mechanism. Once access is gained, the actors engage in device registration within Microsoft Entra ID to establish long-term persistence.

## Attack Chain

1. The threat actor distributes a spearphishing email with a lure mimicking a document signature request (e.g., DocuSign).
2. The email contains a malicious link that redirects the user through a legitimate tracking service (e.g., Monday.com) and a compromised Joomla site to evade reputation filters.
3. The victim is directed to a phishing landing page protected by a Cloudflare Turnstile challenge and a self-signed TLS certificate.
4. The victim enters their credentials and completes the MFA challenge on the AiTM proxy page.
5. The Knight Office kit captures the valid session token and transmits it to the operator console at 104.37.188[.]94.
6. Using the captured session, the threat actor performs a token replay to authenticate to the victim's M365 account.
7. The attacker completes a rogue device registration within Microsoft Entra ID.
8. The attacker binds a Windows Hello for Business key credential to the account to maintain persistent, authenticated access.

## Impact

Successful exploitation allows attackers to gain unauthorized access to Microsoft 365 environments without triggering MFA alerts. This results in potential business email compromise (BEC), data exfiltration, and persistent access that survives password resets. Observed campaigns have successfully compromised at least nine distinct user identities across various organizations.

## Recommendation

Prioritize the identification and blocking of session-theft infrastructure. 
- Block the IP address 104.37.188[.]94 at the network perimeter.
- Audit Microsoft Entra ID logs for unexpected device registrations and unauthorized Windows Hello for Business (WHfB) key bindings.
- Implement FIDO2-based hardware security keys for MFA, as these are resistant to standard AiTM token theft.
- Configure Conditional Access policies to require compliant or managed devices to access sensitive M365 resources.
