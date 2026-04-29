---
title: TeamPCP's CanisterWorm Kubernetes Wiper Targeting Iran
slug: 2026-03-canisterworm-kubernetes-wiper
description: TeamPCP's CanisterWorm is a newly identified Kubernetes wiper targeting Iranian infrastructure, indicating a politically motivated destructive attack.
date: "2026-03-23T12:00:00Z"
type: coverage
types:
  - coverage
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

TeamPCP has deployed a Kubernetes wiper named CanisterWorm, specifically targeting Iranian infrastructure. This destructive malware is designed to obliterate data within Kubernetes environments. The wiper's emergence in March 2026 signals a heightened level of cyber aggression, particularly given the geopolitical context. Defenders need to be aware of the potential for significant operational disruption and data loss. The targeting of Kubernetes environments reflects a sophisticated understanding of modern infrastructure and the increasing reliance on containerization technologies. This campaign requires immediate attention and proactive security measures to mitigate the risk of successful attacks.

## Attack Chain

1. Initial compromise of a node within the Kubernetes cluster, possibly via exploiting a known vulnerability or through compromised credentials.
2. CanisterWorm gains elevated privileges within the compromised node, potentially using techniques such as privilege escalation exploits.
3. Discovery of other nodes and resources within the Kubernetes cluster through reconnaissance activities, leveraging the Kubernetes API.
4. Lateral movement to other nodes using stolen credentials or by exploiting trust relationships between nodes.
5. Execution of CanisterWorm on each targeted node, initiating the data wiping process.
6. Overwriting critical system files and data volumes within the containers and pods.
7. Corruption of Kubernetes configuration files, leading to instability and potential cluster failure.
8. Final stage involves the complete destruction of data within the Kubernetes environment, rendering the affected systems unusable.

## Impact

The successful deployment of CanisterWorm results in widespread data loss and service disruption within the targeted Kubernetes environments. This can lead to significant financial losses, reputational damage, and operational downtime. Given the targeting of Iranian infrastructure, this attack has the potential to impact critical services and government operations. The complete destruction of data necessitates extensive recovery efforts and may result in permanent data loss if backups are not available or are also compromised.

## Recommendation

*   Monitor Kubernetes API server logs for suspicious activity, particularly attempts to list or access sensitive resources to detect reconnaissance (reference: Attack Chain step 3).
*   Implement network segmentation and strict access controls within the Kubernetes cluster to limit lateral movement (reference: Attack Chain step 4).
*   Deploy the Sigma rule `Detect Suspicious Kubernetes Pod Deletion` to identify potential wipe attempts.
*   Review and harden Kubernetes security configurations, including RBAC (Role-Based Access Control) policies, to prevent unauthorized access (reference: Attack Chain step 2).
