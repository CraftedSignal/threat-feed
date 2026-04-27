---
title: Spike in Number of RDP Connections from a Single Source IP
slug: 2024-01-spike-in-rdp-connections
description: A machine learning job detected a high count of destination IPs establishing RDP connections with a single source IP, indicating potential lateral movement attempts after initial compromise.
date: "2024-01-30T12:00:00Z"
severities:
  - low
tags:
  - lateral-movement
  - rdp
  - elastic
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
  - title: Detect RDP Connection to Multiple Hosts from Single Source
    description: Detects a single host initiating RDP connections to multiple distinct internal IP addresses, indicative of lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - network_connection
      - windows
  - title: Detect RDP Client Executing from Uncommon Location
    description: Detects RDP client executable (mstsc.exe) running from an unusual directory, which may indicate malicious execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - lateral_movement
    techniques:
      - T1021.001
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses the potential for lateral movement within a network facilitated by an unusual spike in Remote Desktop Protocol (RDP) connections originating from a single source IP address. This activity is detected using an Elastic machine learning job designed to identify anomalies in network connection patterns. The rule "Spike in Number of Connections Made from a Source IP" leverages this ML job to flag instances where a single host initiates RDP connections to a significantly…
