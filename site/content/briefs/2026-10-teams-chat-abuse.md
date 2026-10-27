---
brief_id: brief-2026-10-27-teams-chat-abuse
event_id: brief-2026-10-27-teams-chat-abuse
revision: 1
activity_at: "2026-10-27T22:05:58Z"
title: 'Microsoft Teams: Social Engineering and Remote Access Abuse'
slug: 2026-10-teams-chat-abuse
description: Threat actors are abusing Microsoft Teams external chat and email bombing to impersonate IT support and facilitate unauthorized remote access to corporate endpoints.
date: "2026-10-27T22:05:58Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: very likely
qa_status:
  verdict: pass
tags:
  - social-engineering
  - teams
  - cloud-security
  - credential-theft
  - lateral-movement
products:
  - Microsoft Teams
  - Quick Assist
  - AnyDesk
  - ScreenConnect
  - Atera
  - Zoho Assist
  - NetSupport Manager
  - LogMeIn
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: Threat actors are abusing Microsoft Teams' external chat functionality at scale, using IT-support impersonation and email bombing tactics to trick employees into granting remote access.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: The impersonator persuades the employee to launch a remote-access session via legitimate tooling like Quick Assist.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
    subtechnique_id: T1558.003
    subtechnique_name: Kerberoasting
    evidence: lateral movement to gain access to credentials through Kerberos abuse methods like Kerberoasting.
    confidence_band: high
references:
  - https://www.darkreading.com/cloud-security/email-bombing-external-teams-chats-repeatable-access-path
rules:
  - title: Detect Microsoft Teams First-Contact External Chat
    description: Detects the creation of a new one-on-one chat with an external participant, a primary indicator for social engineering campaigns where attackers bypass internal communication channels.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.002
    data_sources:
      - network_connection
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review and restrict M365 Teams external access settings to block unmanaged or consumer-grade accounts
      owner: IT Operations
      due: 48h
      evidence: Vendor recommendation for hardening the external chat path
  hunt_leads:
    - lead: Identify abnormal RMM tool execution (AnyDesk, Atera, Zoho, etc.) initiated by users following Teams chat sessions
      technique_id: T1219
      data_needed:
        - Process creation logs for remote access binaries
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Victims are persuaded to launch remote-access session via legitimate tooling.
  mitigation_plan:
    - priority: immediate
      action: Enable M365 Unified Audit Logs and configure alerts for ChatCreated events
      owner: SOC
      addresses: Initial access vector
      evidence: Arctic Wolf identifies ChatCreated as primary detection point
---

Threat actors are conducting a wide-scale social engineering campaign by abusing Microsoft Teams' external chat functionality. The attack typically begins with "email bombing" to overwhelm the victim, followed by an external Teams message from an account impersonating "IT Support." Victims are persuaded to grant remote access via legitimate software, which attackers subsequently leverage to execute PowerShell payloads, steal credentials, and perform lateral movement.

## Attack Chain
1. **Preparation**: Attackers initiate email bombing to create a sense of urgency for the victim.
2. **Initial Contact**: Attackers use external Teams chat to impersonate internal IT Support (often appending "(Internal)" to their display name).
3. **Social Engineering**: The attacker persuades the user to initiate a remote-access session using tools like Quick Assist, AnyDesk, or ScreenConnect.
4. **Remote Access**: The victim shares their screen, granting the attacker control over the endpoint.
5. **Discovery**: Attackers perform initial reconnaissance using commands such as `whoami` and `systeminfo`.
6. **Payload Execution**: Attackers deploy PowerShell-based payloads and establish a Command and Control (C2) beacon.
7. **Persistence and Lateral Movement**: Attackers utilize secondary remote access tools and abuse Kerberos mechanisms (e.g., Kerberoasting) to move laterally within the network.

## Recommendation
* Monitor for Microsoft Teams `ChatCreated` events involving external participants, specifically those originating from unmanaged or consumer-grade accounts.
* Hardening: Disable the option allowing unmanaged users to start conversations with internal users.
* Hardening: Implement an allowlist for trusted external organizations and block federation with trial-only tenants.
* Training: Educate users on identifying the "External" tag in Teams and establishing standard procedures for how IT support initiates contact.
