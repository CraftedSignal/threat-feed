---
brief_id: brief-2026-10-26-m365-token-replay
event_id: brief-2026-10-26-m365-token-replay
revision: 2
activity_at: "2026-10-29T00:00:24Z"
revision_history:
  - revision: 2
    at: "2026-10-29T00:00:24Z"
    checksum: sha256:53f9ebcd00ff79030678ae3c0e60288bf309e891017443f560ad7325921c032f
    summary: new IOCs
    changed_fields:
      - claim_state
      - iocs
      - lastmod
      - references
      - threat_actor
      - updates
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/al26-028-ongoing-help-desk-voice-phishing-campaign-targeting-canadian-organizations
title: Microsoft 365 Adversary-in-the-Middle Token Replay Campaign
slug: 2026-10-m365-token-replay
description: Threat actors are leveraging Adversary-in-the-Middle relays to capture M365 authentication tokens and bypass MFA, resulting in unauthorized account access, rogue device registration, and malicious inbox rule creation across multiple organizations.
date: "2026-10-26T09:54:31Z"
lastmod: "2026-10-28T23:59:28Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
actors:
  - UNC6671
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - phishing
  - cloud-security
  - aitm
  - token-theft
  - m365
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
    evidence: The attack has been found to employ an AitM login page, which sits between the victims and legitimate Microsoft infrastructure.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.003
    technique_name: Cloud Account
    evidence: In no less than 19 organizations, the victim's existing MFA methods were removed and a new method registered within three hours of the first sign-in.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098.002
    technique_name: Additional Email Delegate Permissions
    evidence: The threat actor registered at least 48 fake computers in victim organizations' Microsoft directories.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550.001
    technique_name: Application Access Token
    evidence: The end goal is to collect the access token issued by Microsoft following the sign-in process so that it doesn't have to bypass MFA a second time.
    confidence_band: high
references:
  - https://thehackernews.com/2026/10/microsoft-365-token-replay-attacks.html
  - https://cyber.gc.ca/en/alerts-advisories/al26-028-ongoing-help-desk-voice-phishing-campaign-targeting-canadian-organizations
iocs:
  - type: ip
    value: 193.26.115.221
  - type: domain
    value: exy.sh
  - type: domain
    value: onetimesso.com
  - type: domain
    value: registermymfa.com
ioc_counts:
  domain: 3
  ip: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit Entra device registration logs for rogue devices registered within the last 90 days.
      owner: SOC
      due: 24h
      evidence: The threat actor registered at least 48 fake computers in victim organizations' Microsoft directories.
    - action: Scan mailbox rules for obfuscated names or keywords like payroll, deposit, and bonus.
      owner: SOC
      due: 24h
      evidence: Furthermore, the attackers have also been spotted setting up hidden email rules in victims' inboxes with names such as ".," "sss," "ss," "iT," ",.," "........," "s," and "d".
  hunt_leads:
    - lead: Hunt for suspicious Microsoft 365 sign-in events characterized by mismatched user-agent strings or geolocation anomalies following MFA events.
      technique_id: T1550.001
      data_needed:
        - Microsoft Entra Sign-in logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Rather than guessing passwords, the attacker replayed sign-in tokens stolen from victims.
  mitigation_plan:
    - priority: immediate
      action: Implement Conditional Access policies requiring MFA for all users, all cloud apps, and all client app types, and restrict device-code workflow.
      owner: IT Operations
      addresses: Token Replay / AitM
      evidence: Businesses setting up CAPs should require MFA (or block) for All Users, All Cloud Apps, and All Client App types, unconditionally.
updates:
  - at: "2026-10-28T23:59:28Z"
    level: L1
    summary: new IOCs
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/al26-028-ongoing-help-desk-voice-phishing-campaign-targeting-canadian-organizations
---

Between July 14 and September 22, 2026, threat actors conducted a widespread campaign targeting Microsoft 365 users. The attackers utilized Adversary-in-the-Middle (AitM) infrastructure to intercept login credentials and MFA codes, allowing them to capture valid session tokens. These tokens were subsequently replayed to gain access to corporate mailboxes without triggering MFA. The campaign resulted in the compromise of 97 accounts across 79 organizations, with observed persistence mechanisms including the registration of rogue Entra devices and the addition of unauthorized MFA methods.

## Attack Chain
1. Victims are directed to a malicious AitM login page that proxies communication with legitimate Microsoft services.
2. The AitM proxy captures the victim's credentials, MFA inputs, and the resulting valid session access token.
3. Attackers replay the captured access token from their own infrastructure within minutes to hijack active sessions.
4. Attackers gain unauthorized access to Microsoft 365 services and proceed to establish long-term persistence.
5. Attackers register rogue Entra devices and add unauthorized authenticator apps to maintain access even after session expiration.
6. Attackers configure hidden inbox rules to delete or hide sensitive communications (e.g., payroll, bonus) and distribute outbound spam.

## Impact
The campaign successfully compromised 97 accounts across 79 organizations. Attackers registered at least 48 fake devices in victim directories and leveraged compromised mailboxes for outbound spam campaigns. Specific inbox rules were used to obfuscate activity and hide incoming financial communications.

## Recommendation
- Restrict the device-code authentication workflow using Microsoft Entra Conditional Access policies to prevent unauthorized device registration.
- Audit Microsoft Entra directories for unauthorized or suspicious registered devices.
- Review and enforce MFA requirements using Conditional Access policies for all users, all cloud apps, and all client app types unconditionally.
- Implement periodic audits of inbox rules across the environment, specifically searching for rules with minimal naming or obscured characters.
- Immediately revoke active sessions and reset credentials for any accounts identified with suspicious MFA registration activity.
