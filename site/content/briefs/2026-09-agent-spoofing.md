---
title: Detection of Elastic Agent ID Spoofing and Data Manipulation
slug: 2026-09-agent-spoofing
description: This threat brief details the detection of potential agent spoofing, where an adversary hijacks an Elastic Agent ID to inject illegitimate data or masquerade activity across multiple hosts.
date: "2026-09-18T19:09:09Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Elastic
products:
  - Elastic Agent (>= 7.14)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Adversaries may exploit these agents by hijacking their IDs to inject false data, masking malicious actions.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: This could occur in the event of an agent being taken over and used to inject illegitimate documents into an instance.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/defense_evasion_agent_spoofing_multiple_hosts.toml
rules:
  - title: Detect Multiple Hosts Reporting Same Elastic Agent ID
    description: Detects potential agent spoofing by identifying when multiple unique host IDs report telemetry using the same Elastic Agent ID.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1036
    data_sources:
      - endpoint
      - windows|linux|macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy rule for detection of multiple hosts per agent ID
      owner: Detection Engineering
      due: 48h
      evidence: Source detection rule requirement
  mitigation_plan:
    - priority: medium_term
      action: Audit virtual machine templates to ensure unique agent ID generation
      owner: IT Operations
      addresses: T1036
      evidence: False positive analysis in source
---

Adversaries may attempt to evade detection by hijacking legitimate security agent IDs. By utilizing a compromised Agent ID across multiple endpoints, an attacker can inject fraudulent telemetry or manipulate existing logs. This activity allows malicious actors to masquerade as trusted systems, effectively poisoning the data ingested by the SIEM. This detection capability focuses on identifying the anomalous reuse of a single Elastic Agent ID (Elastic Agent version 7.14 and later) across multiple distinct host identifiers. This behavior is a common indicator of unauthorized data manipulation or masquerading attempts intended to conceal malicious operations from security analysts.

## Impact

Successful agent spoofing leads to a compromised security visibility posture. By injecting illegitimate documents or masking malicious actions, attackers can effectively blind SOC teams, delay incident response, and maintain persistence. This behavior is observed as a critical threat to data integrity, as it undermines the reliability of logs used for forensic investigation and real-time detection. If left unmonitored, this technique facilitates the seamless execution of other malicious activities across the enterprise network.

## Recommendation

Detection engineering teams should deploy rules to identify distinct hosts reporting the same Agent ID. 

- Deploy the provided detection logic to monitor for multiple unique host IDs mapped to a single agent ID.
- Audit virtual infrastructure to ensure that snapshots, clones, or gold images have unique Agent IDs provisioned upon deployment.
- Maintain a centralized registry of authorized Agent IDs and cross-reference alerts against this list during triage.
- Implement isolation procedures for any host identified as an agent-spoofing participant until the source of the duplication is verified.
