---
brief_id: brief-2026-11-12-screenconnect-attacks
event_id: brief-2026-11-12-screenconnect-attacks
revision: 1
activity_at: "2026-11-12T06:12:36Z"
title: Unauthorized Access and Rogue Client Deployment in ScreenConnect Environments
slug: 2026-11-screenconnect-attacks
description: Threat actors are leveraging compromised credentials or hijacked operator sessions to gain access to ScreenConnect panels, where they deploy rogue clients and malicious toolkits for persistent access.
date: "2026-11-12T06:12:36Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://thehackernews.com/2026/11/screenconnect-attacks-target-at-least.html
  observed_at: "2026-11-11T17:47:00Z"
  confidence: high
source_assessment:
  reliability: D
  credibility: "2"
  rating: D2
  likelihood: likely
tags:
  - screenconnect
  - malware
  - persistence
  - lateral-movement
vendors:
  - ConnectWise
products:
  - ScreenConnect
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Current telemetry points to compromised credentials or hijacked operator sessions to gain initial access.
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: ScreenConnect scripts staging batch files and using PowerShell with execution-policy bypass to retrieve a second-stage script.
references:
  - https://thehackernews.com/2026/11/screenconnect-attacks-target-at-least.html
rules:
  - title: Suspicious ScreenConnect Run Command Activity
    description: Detects the use of Run Command to deploy suspected malicious scripts associated with the SCKit toolkit.
    platform: sigma
    severity: critical
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

ConnectWise is investigating reports of unauthorized access to ScreenConnect environments, affecting at least 288 endpoints across 48 organizations. The activity involves the use of the 'Run Command' feature to deploy rogue ScreenConnect clients. ConnectWise has urged partners to disable five third-party extensions as a precautionary measure while investigations continue.

## Attack Chain
1. Initial Access: Attackers gain access to cloud-hosted ScreenConnect panels, likely via compromised credentials or hijacked operator sessions.
2. Payload Delivery: Attackers utilize the 'Run Command' feature to deploy rogue ScreenConnect clients and an encrypted malicious toolkit (SCKit).
3. Persistence and Lateral Movement: The toolkit creates a persistent backdoor, adds Microsoft Defender exclusions, and attempts to steal browser sessions and authentication tokens from connected technician workstations to pivot to other managed panels.

## Recommendation
- Disable the identified third-party extensions: Labtech Plus, RMM Plus, RMM+, RMM Plus Password Link, and RMM+ Password Link.
- Review ScreenConnect Run Command history for unauthorized activity.
- Monitor for suspicious sign-ins, unexpected MFA prompts, and new administrator accounts.
- Inspect managed endpoints for the presence of unauthorized ScreenConnect clients or unexpected tools such as 'TrapWatch'.
