---
brief_id: brief-2026-11-13-teams-device-code-phishing
event_id: brief-2026-11-13-teams-device-code-phishing
revision: 1
activity_at: "2026-11-13T16:06:43Z"
title: Microsoft Teams Meeting Booking Flow Used for Device Code Phishing
slug: 2026-11-teams-device-code-phishing
description: Threat actors are using deceptive Microsoft Teams meeting-scheduling pages to trick victims into completing a device code authentication flow, allowing for the theft of session tokens.
date: "2026-11-13T16:06:43Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing
  observed_at: "2026-11-13T16:06:43Z"
  confidence: medium
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Microsoft Teams
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: The threat actor delivered a targeted email leveraging a multi-stage redirect chain to bypass security controls
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: The device code flow hands the threat actor tokens for the Microsoft Authentication Broker client once the victim enters the code on Microsoft's genuine page.
references:
  - https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing
action_plan:
  hunt_leads:
    - lead: Identify spear-phishing attempts by filtering for email traffic containing multi-stage redirect chains, specifically targeting Microsoft Safe Links (nam12.safelinks.protection.outlook.com) that point to URL shortening services (e.g., share.google) before resolving to external, non-Microsoft domains.
      technique_id: T1566
      data_needed:
        - Email Security/Gateway Logs
        - Microsoft 365 Unified Audit Log
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The threat actor delivered a targeted email leveraging a multi-stage redirect chain to bypass security controls, routing the initial Microsoft Safe Links-wrapped URI through a Google short link (share[.]google/?q=UltJkMsVWI5V9GJM1) and www.google[.]com/share.google before landing on a malicious lure.
    - lead: Audit Microsoft 365 sign-in logs for authentication events associated with 'Cmsi:Cmsi' (Device Code Flow) occurring from unrecognized residential proxy IPs or atypical ASN/region combinations. Look for subsequent non-interactive sign-ins utilizing suspicious programmatic User Agents (e.g., python-requests, node) shortly after the device code validation.
      technique_id: T1528
      data_needed:
        - Microsoft Entra ID (Azure AD) Sign-in Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The device code flow hands the threat actor tokens for the Microsoft Authentication Broker client once the victim enters the code on Microsoft's genuine page... we also observed the Device code (Cmsi:Cmsi) login being routed through a residential callback proxy... Subsequent Programmatic User Agents such as python-requests and node in the sign in logs indicates automated infrastructure.
---

In mid-October 2026, threat actors targeted a construction sector organization using a spear-phishing email that impersonated a senior executive from a peer company. The email contained a link leading to a typosquatted domain designed to simulate a Microsoft Teams meeting-scheduling interface. 

## Attack Chain
1. The attacker utilized a spear-phishing link embedded in a multi-stage redirect chain.
2. The landing page presented a fake 'Microsoft Teams Meeting Scheduler' interface that prompted users to select meeting details.
3. Upon user interaction, the backend initiated a Microsoft device code sign-in process. The site copied the resulting user code to the victim's clipboard.
4. The site redirected the victim to the legitimate Microsoft device login page to enter the code, which authorized the attacker's session.

## Impact
The attack enables the theft of session tokens via the device code authentication flow, potentially granting attackers access to victim accounts.

## Recommendation
Defenders should monitor sign-in logs for the 'Cmsi:Cmsi' indicator, which signals device-code authentication. Organizations should investigate authentication attempts originating from unmanaged devices or unexpected infrastructure and consider restricting device code flows where not required through Conditional Access policies.
