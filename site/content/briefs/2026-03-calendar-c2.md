---
title: China-Nexus Campaign Using Google Calendar as C2
slug: 2026-03-calendar-c2
description: A China-nexus threat actor is utilizing Google Calendar as a command and control (C2) infrastructure to conduct stealthy operations.
date: "2026-03-21T00:00:00Z"
severities:
  - high
actors:
  - China-nexus actor
tags:
  - google-calendar
  - c2
  - china-nexus
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data from Configuration Repository
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573
    technique_name: Encrypted Channel
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.reddit.com/r/blueteamsec/comments/1ryo67d/google_calendar_as_c2_infrastructure_chinanexus/
  - https://www.virusbulletin.com/uploads/pdf/conference/vb2025/papers/Google-Calendar-as-C2-infrastructure-a-China-nexus-campaign-with-stealthy-tactics.pdf
rules:
  - title: Detect Google Calendar Modifications by Unusual Processes
    description: Detects processes that are not typically associated with Google Calendar making changes to calendar events.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Google Calendar API Calls
    description: Detects network connections to Google Calendar API endpoints from unusual processes.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A China-nexus threat actor has been observed leveraging Google Calendar as a novel command and control (C2) mechanism. This campaign, observed starting in 2025, uses calendar entries to relay commands to compromised hosts. The use of Google Calendar allows the attacker to blend in with legitimate network traffic, evade traditional C2 detection methods, and maintain persistence. The stealthy nature of this approach makes it difficult to detect and attribute. This technique is particularly…
