---
title: Detection of Newly Observed Processes with High CPU Usage
slug: 2026-09-newly-observed-high-cpu-process
description: This detection capability monitors for unauthorized resource hijacking, such as cryptomining or exploit payload execution, by identifying new processes exhibiting sustained CPU usage above 90 percent.
date: "2026-09-18T19:18:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - impact
  - resource-hijacking
  - cryptomining
  - detection-rule
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
    evidence: A previously unseen process consuming sustained CPU resources may indicate suspicious activity such as cryptomining, exploit payload execution, or other forms of resource abuse following host compromise.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy System integration to gather process-level CPU telemetry.
      owner: Detection Engineering
      due: 72h
      evidence: Rule setup requirements document the need for System integration metrics.
  hunt_leads:
    - lead: Identify all processes running at >90% CPU that lack a known-good cryptographic signature.
      technique_id: T1496
      data_needed:
        - Process CPU usage
        - Process hash
        - File reputation
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Sustained CPU usage is a primary indicator of resource hijacking.
  mitigation_plan:
    - priority: short_term
      action: Establish a baseline of authorized high-CPU applications to filter false positives.
      owner: Detection Engineering
      addresses: Resource Hijacking
      evidence: Triage and analysis section lists software updates and security scans as common false positives.
---

This detection rule identifies suspicious host activity by monitoring for processes that exhibit sustained CPU usage exceeding 90 percent and have been observed for the first time within a 5-day window. This behavior is a common indicator of post-compromise resource hijacking, specifically unauthorized cryptomining or the execution of resource-intensive exploit payloads. By focusing on newly observed processes, the rule effectively filters out established system or application baseline behaviors.

Defenders should use this signal to surface potential indicators of host compromise where an attacker has introduced new tooling that significantly degrades system performance. While effective for detecting malicious resource abuse, this detection may also identify unexpected legitimate software deployments, requiring analysts to differentiate between intended performance degradation and malicious activity.

## Impact

Successful resource hijacking can lead to significant degradation of system and application performance, increased operational costs, and the potential for a compromised host to be used as a platform for further network lateral movement or data exfiltration. If left unmitigated, these threats can persist across an enterprise environment, affecting server availability and increasing the risk of larger-scale security incidents.

## Recommendation

Prioritized actions for detection and response teams:

- Deploy the Elastic Agent with the 'System' integration enabled to collect `system.process` and `system.cpu` metrics.
- Implement the provided ESQL detection logic to monitor for newly observed processes exceeding 90 percent CPU usage.
- Establish an investigative workflow to cross-reference identified processes against known-good baseline hash lists and expected binary paths.
- Monitor for process ancestry that links these high-CPU spikes to unauthorized child-process spawning or unexpected persistence mechanisms (services, scheduled tasks).
- Isolate hosts identified with confirmed malicious activity to prevent the spread of resource hijacking or further malicious payload delivery.
