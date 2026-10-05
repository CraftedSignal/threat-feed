---
title: Detection of Potentially Unwanted Application (PUA) via HTTP User-Agent Analysis
slug: 2026-10-http-pua-user-agents
description: This detection analytic identifies Potentially Unwanted Applications by monitoring for specific HTTP User-Agent strings in web logs, which can signify unauthorized tool usage or active compromise on the network.
date: "2026-10-05T12:35:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - pua
  - network-security
  - anomaly-detection
  - c2
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The detection of these specific User-Agent strings can indicate the use of unauthorized tools or potentially compromised hosts, mapping to MITRE ATT&CK technique T1071.001.
    confidence_band: high
action_plan:
  priority: enrich_before_decision
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review current proxy/web log ingestion to ensure User-Agent data is present in the Web Datamodel.
      owner: Detection Engineering
      due: 72h
      evidence: Source documentation for implementation requirements.
  enrichment_needed:
    - item: PUA User-Agent reference list
      owner: CTI
      reason: Ensure the detection utilizes the most current list of malicious/unwanted User-Agents.
      evidence: Source references an external community-maintained list.
  hunt_leads:
    - lead: Identify all unique User-Agent strings in the last 30 days and cross-reference with known PUA lists.
      technique_id: T1071.001
      data_needed:
        - Proxy/Web server logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Analytic story covers suspicious user agents.
---

This detection focuses on identifying the use of Potentially Unwanted Applications (PUA) by analyzing HTTP User-Agent headers found within web or proxy logs. Attackers often utilize specific tools during the reconnaissance, exploitation, or C2 phases of an intrusion, many of which transmit unique or recognizable User-Agent strings. The presence of these identifiers in corporate network traffic is frequently associated with malicious activity, including ransomware operations such as BlackSuit and Cactus, as well as privilege escalation attempts. By comparing incoming User-Agent strings against a known list of PUA signatures, security teams can pinpoint endpoints that are either running unauthorized software or are being utilized as proxies for malicious infrastructure. This detection capability is designed to trigger when a host performs a request using a User-Agent associated with known unwanted software, allowing for early intervention in the intrusion lifecycle.

## Impact

Successful exploitation of compromised hosts or the execution of PUA can lead to unauthorized data exfiltration, lateral movement, or the deployment of ransomware. Identifying these tools early allows defenders to isolate affected assets before threat actors can achieve their final objectives, such as encryption or long-term persistence in the environment.

## Recommendation

1. Implement ingestion of web and proxy logs into your security platform's Web Datamodel to facilitate centralized traffic analysis.
2. Deploy the provided detection logic to flag occurrences of PUA-associated User-Agents within the network environment.
3. Establish an allowlist for known-good, internally developed tooling that may use non-standard User-Agents to reduce noise in high-traffic environments.
4. Perform investigation on hosts identified as sources of PUA traffic, focusing on the parent process that initiated the network request to determine if the activity is authorized.
