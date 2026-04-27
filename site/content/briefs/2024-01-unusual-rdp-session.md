---
title: Unusual Time or Day for an RDP Session Detected by Machine Learning
slug: 2024-01-unusual-rdp-session
description: A machine learning job detected an RDP session initiated at an unusual time or day, potentially indicating lateral movement activity within a network.
date: "2024-01-03T18:50:00Z"
severities:
  - low
tags:
  - lateral-movement
  - threat-detection
  - windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/lmd
  - https://www.elastic.co/blog/detecting-lateral-movement-activity-a-new-kibana-integration
  - https://www.elastic.co/blog/remote-desktop-protocol-connections-elastic-security
rules:
  - title: Detect RDP Connection from Uncommon Process
    description: Detects RDP connections initiated by processes that are not typically associated with RDP.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Network Connection to RDP Port by Uncommon Process
    description: Detects network connections to the RDP port (3389) initiated by processes not typically associated with RDP. This may indicate lateral movement or exploitation of RDP services.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This alert originates from a machine learning job designed to detect anomalous RDP session start times. RDP is a common vector for lateral movement, and attackers may initiate sessions during off-peak hours to evade detection. The machine learning model flags sessions started outside of normal business hours or on unusual weekdays. While not inherently malicious, this activity warrants investigation as it can be an early indicator of a broader attack. The rule is part of the Lateral Movement…
