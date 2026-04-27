---
title: TeamPCP's CanisterWorm Kubernetes Wiper Targeting Iran
slug: 2026-03-canisterworm-kubernetes-wiper
description: TeamPCP's CanisterWorm is a newly identified Kubernetes wiper targeting Iranian infrastructure, indicating a politically motivated destructive attack.
date: "2026-03-23T12:00:00Z"
severities:
  - critical
actors:
  - TeamPCP
tags:
  - kubernetes
  - wiper
  - iran
  - canisterworm
  - teampcp
  - destructive-attack
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://www.reddit.com/r/netsec/comments/1s0lvk9/canisterworm_gets_teeth_teampcps_kubernetes_wiper/
  - https://www.aikido.dev/blog/teampcp-stage-payload-canisterworm-iran
rules:
  - title: Detect Suspicious Kubernetes Pod Deletion
    description: Detects attempts to delete multiple pods within a short timeframe, which may indicate a wiper attack.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - network_connection
      - kubernetes
  - title: Detect Suspicious Executions inside Kubernetes Pods
    description: Detects execution of unusual or suspicious binaries within Kubernetes pods, potentially indicating malicious activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

TeamPCP has deployed a Kubernetes wiper named CanisterWorm, specifically targeting Iranian infrastructure. This destructive malware is designed to obliterate data within Kubernetes environments. The wiper's emergence in March 2026 signals a heightened level of cyber aggression, particularly given the geopolitical context. Defenders need to be aware of the potential for significant operational disruption and data loss. The targeting of Kubernetes environments reflects a sophisticated…
