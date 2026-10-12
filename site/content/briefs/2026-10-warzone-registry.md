---
title: Warzone RAT Registry Modification for Connection Persistence
slug: 2026-10-warzone-registry
description: The Warzone RAT malware modifies Windows registry keys related to connection limits to facilitate lateral movement and network-based attacks.
date: "2026-10-12T18:12:47Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Warzone RAT
tags:
  - malware
  - rat
  - registry
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The analytic identifies a suspicious modification of the Windows registry setting for max connections per server.
    confidence_band: high
references:
  - https://asec.ahnlab.com/en/17692/
  - https://www.blackberry.com/us/en/solutions/endpoint-security/ransomware-protection/warzone
rules:
  - title: Detect Registry Modification for MaxConnectionsPerServer
    description: Detects modification of the MaxConnectionsPerServer registry key, often performed by Warzone RAT to increase network concurrency.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy registry monitoring rules for the identified keys
      owner: Detection Engineering
      due: 48h
      evidence: Source explicitly flags these keys as indicators of Warzone RAT activity.
  hunt_leads:
    - lead: Search for existing registry modifications to MaxConnectionsPerServer across endpoints
      technique_id: T1112
      data_needed:
        - Sysmon Event ID 13 logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source documents this as an anomaly indicating potential compromise.
---

Warzone RAT (also known as Ave Maria) is a remote access trojan that functions as both a credential stealer and a tool for unauthorized network activity. It has been observed modifying specific Windows registry settings, specifically 'MaxConnectionsPerServer' and 'MaxConnectionsPer1_0Server' located under 'Internet Settings'. By setting these values to '0x0000000a', the malware increases the allowable concurrent connections to a remote server. This modification is significant for defenders as it enables attackers to perform more effective lateral movement, maintain stable command-and-control communication, or participate in distributed denial-of-service (DDoS) campaigns. This activity represents a clear attempt to reconfigure system network behavior to better suit the malicious objectives of the RAT.

## Impact

Successful exploitation of this registry modification allows the Warzone RAT to evade standard connection throttling limits, enabling persistent and high-volume communication with attacker-controlled infrastructure. This configuration change impacts the security posture of the host by facilitating unauthorized lateral movement across the enterprise network and increasing the potential for the compromised system to be used as a node in network-based attacks.

## Recommendation

1. Deploy the provided Sigma rule to detect unauthorized modifications to the 'Internet Settings' registry keys.
2. Baseline the standard 'MaxConnectionsPerServer' registry values across your environment to identify systems that deviate from your organizational configuration.
3. Monitor Sysmon Event ID 13 for registry set operations targeting the specific paths identified in this brief.
