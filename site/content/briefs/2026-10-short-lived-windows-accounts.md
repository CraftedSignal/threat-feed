---
title: Detection of Rapid Creation and Deletion of Windows Accounts
slug: 2026-10-short-lived-windows-accounts
description: This detection targets the suspicious lifecycle of Windows user accounts created and deleted within one hour, a technique often used by attackers to gain ephemeral unauthorized access or maintain persistence while evading long-term detection.
date: "2026-10-12T17:58:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - initial-access
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: This behavior is significant as it may indicate an attacker attempting to create and remove accounts quickly to evade detection or gain unauthorized access.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This behavior is significant as it may indicate an attacker attempting to create and remove accounts quickly to evade detection or gain unauthorized access.
    confidence_band: high
rules:
  - title: Detect Rapid Windows Account Creation and Deletion
    description: Detects the creation and subsequent deletion of a user account on a Windows host within a 60-minute window.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1136.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the analytic to monitor for Event ID 4720 and 4726 within a 1-hour window.
      owner: Detection Engineering
      due: 72h
      evidence: Source document identifies these event IDs as key telemetry for the detection.
  hunt_leads:
    - lead: Audit existing Windows Security logs for accounts created and deleted by non-standard administrative service accounts.
      technique_id: T1136.001
      data_needed:
        - Windows Security Event Logs (4720, 4726)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source highlights account lifecycle manipulation as an indicator of attacker presence.
  mitigation_plan:
    - priority: medium
      action: Implement strict change management for account creation and restrict usage of local administrator rights.
      owner: IT Operations
      addresses: T1136.001
      evidence: Reducing the window for administrative account creation minimizes the opportunity for abuse.
---

Attackers frequently abuse the capability to create and remove user accounts to facilitate malicious operations, such as privilege escalation, lateral movement, or maintaining temporary persistence. By performing these actions in rapid succession, actors aim to minimize their footprint and evade security monitoring that focuses on long-term account activity. This analytic specifically tracks the creation (Event ID 4720) and subsequent deletion (Event ID 4726) of local or domain user accounts within a 60-minute window. This behavior is highly characteristic of automated scripts or manual administrative abuse where an adversary creates a backdoor account, performs a secondary action, and then removes the account to leave no trace. Defenders should investigate these events to differentiate between authorized administrative cleanup and malicious account lifecycle manipulation.

## Attack Chain

1. Attacker gains initial access to a Windows host or domain controller.
2. Attacker executes net user /add or invokes the API to create a new local or domain account.
3. Security event 4720 (User account created) is generated in the Windows Security log.
4. Attacker leverages the new account to conduct unauthorized activities (e.g., file access, lateral movement).
5. Attacker executes net user /delete or invokes the API to remove the account.
6. Security event 4726 (User account deleted) is generated in the Windows Security log.
7. Attacker objective (e.g., exfiltration, persistence) is achieved or abandoned.

## Impact

Successful exploitation of ephemeral account creation allows attackers to bypass security monitoring designed for persistent accounts. This technique is often associated with unauthorized access, privilege escalation, and lateral movement. Failure to detect this activity can result in persistent threats remaining undetected within the network, as the evidence of the account existence is removed shortly after use.

## Recommendation

Prioritized actions for detection and investigation teams:
- Deploy the logic monitoring for Event IDs 4720 followed by 4726 within a 60-minute interval on all critical endpoints and domain controllers.
- Enable Group Management Audit Logs in the Local Windows Security Policy to ensure these events are generated and captured by the SIEM.
- Investigate every instance of short-lived account creation, correlating the event with the source user (`src_user`) and the account created (`user`) to determine if the activity aligns with documented administrative tasks.
- Adjust the `maxspan` and time window parameters to account for specific environment baseline activity.
