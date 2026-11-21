---
brief_id: brief-2026-11-17-cold-relic
event_id: brief-2026-11-17-cold-relic
revision: 2
activity_at: "2026-11-21T09:56:59Z"
revision_history:
  - revision: 2
    at: "2026-11-21T09:56:59Z"
    checksum: sha256:3b767c22214623145c863adeb21dc917660692635537029815609d0930b66271
    summary: exploited:true
    changed_fields:
      - exploitation_evidence
      - lastmod
      - references
      - updates
    source_urls:
      - https://thehackernews.com/2026/11/russian-cold-relic-hackers-use-stolen.html
title: 'COLD RELIC: Long-term Espionage via Cloud Impersonation and Credential Abuse'
slug: 2026-11-cold-relic
description: Russian state-sponsored actor COLD RELIC is leveraging compromised cloud identities and stolen data from initial victims to conduct highly targeted, persistent social engineering and follow-on espionage campaigns across organizations.
date: "2026-11-17T20:55:52Z"
lastmod: "2026-11-21T09:56:39Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - COLD RELIC
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://thehackernews.com/2026/11/russian-cold-relic-hackers-use-stolen.html
  observed_at: "2026-11-18T05:58:04Z"
  confidence: medium
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Content verified against Mandiant source.
has_poc: true
tags:
  - espionage
  - cloud
  - phishing
  - identity-theft
vendors:
  - Google
  - Microsoft
products:
  - Google Workspace
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: A COLD RELIC phishing link usually contains a parameter on the end of it with a value that is set by the attacker and often indicates a relationship to a previous victim or what the lure is.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: COLD RELIC authenticated using the stolen credentials of a Super Admin account, in combination with a multi-factor authentication (MFA) push notification fatigue attack.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.004
    subtechnique_name: Cloud Accounts
    evidence: COLD RELIC leveraged passkeys, MFA backup codes, and rogue MFA devices to retain access throughout the intrusion.
    confidence_band: high
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/cold-relic-a-case-study-in-impersonation-and-compromise/
  - https://thehackernews.com/2026/11/russian-cold-relic-hackers-use-stolen.html
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Cloud Security
  hunt_leads:
    - lead: Hunt for unusual device registration activity within Microsoft Entra ID or Google Workspace, specifically focusing on MFA devices registered by accounts in high-privilege roles.
      technique_id: T1078
      data_needed:
        - Google Workspace Admin Audit Logs
        - Microsoft Entra ID Sign-in and Audit Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: COLD RELIC registered a device model previously unseen within the tenant of the victim organization.
    - lead: Identify anomalous use of administrative tools for mass data export, specifically searching for CUSTOMER_TAKEOUT_CREATED events or unusual file sharing patterns.
      technique_id: T1070
      data_needed:
        - Google Workspace Admin Audit Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: COLD RELIC exported full employee lists and initiated a domain-wide data export via Google Workspace Customer Takeout using Super Admin privileges.
updates:
  - at: "2026-11-21T09:56:39Z"
    level: L3
    summary: exploited:true
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/11/russian-cold-relic-hackers-use-stolen.html
---

## Overview
COLD RELIC, a Russian state-sponsored threat actor, has been observed conducting multi-stage espionage operations against high-value targets in Europe and North America. The group specializes in cloud productivity environment compromise, using stolen data and identity context from one victim to build authentic pretexts for spear-phishing subsequent targets. Their tradecraft includes the use of residential proxies, MFA push notification fatigue, and unauthorized registration of MFA devices or passkeys to maintain long-term persistence within target tenants.

## Attack Chain
1. Initial reconnaissance using stolen data (contacts, email archives) from prior victims to establish credible pretexts.
2. Initial access gained via spear-phishing campaigns or MFA push notification fatigue against cloud identities.
3. Threat actor authentication using stolen credentials in combination with residential proxy networks to evade location-based detection.
4. Enrollment of malicious MFA devices, passkeys, or rogue OAuth tokens to secure long-term persistence across SSO and federated providers.
5. Exfiltration of cloud-stored data, including employee lists and email archives, via administrative tools like Google Workspace Customer Takeout.
6. Antiforensics activity involving the modification or deletion of security audit logs and Alert Center notifications.
7. Use of impersonated accounts to initiate contact with new targets via secure messaging platforms and redirectors for further credential theft.

## Impact
COLD RELIC consistently maintains a high operational tempo, gaining access to strategic information from defense contractors, government officials, and NGOs. The actor's ability to pivot between federated cloud environments and leverage trusted relationships (impersonation) facilitates the compromise of high-value professional networks.

## Recommendation
- Audit and monitor Google Workspace Admin logs for 'CUSTOMER_TAKEOUT_CREATED' events and unusual admin-level data exports.
- Restrict administrative access to cloud environments and implement robust, phishing-resistant MFA (such as FIDO2 security keys) to mitigate push fatigue and rogue device enrollment.
- Review authentication logs for anomalous device registrations or passkey enrollments that deviate from organizational baselines.
- Educate employees on the risks of social engineering involving contacts from trusted third parties, particularly through secure messaging applications.
- Monitor for unauthorized OAuth applications or external email client syncing (IMAP/POP) within tenant configurations.
