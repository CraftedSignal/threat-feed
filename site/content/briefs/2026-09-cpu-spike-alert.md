---
title: Detection of Security Alerts Correlated with High CPU Utilization
slug: 2026-09-cpu-spike-alert
description: A cross-platform detection methodology correlates security alerts with processes exhibiting sustained high CPU utilization to identify potential resource abuse or post-compromise activity.
date: "2026-09-18T19:18:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - threat-detection
  - impact
  - system-monitoring
  - resource-abuse
  - cryptomining
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
    evidence: This behavior may indicate malicious activity such as malware execution, cryptomining, exploit payload execution, or abuse of system resources following initial compromise.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable System integration and CPU metrics collection for high-value endpoints
      owner: Detection Engineering
      due: 72h
      evidence: Rule requires host CPU metrics collected via the Elastic Agent System integration
  hunt_leads:
    - lead: Identify processes with >70% CPU usage that have triggered security alerts
      technique_id: T1496
      data_needed:
        - CPU utilization metrics
        - Security alert logs
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: The rule identifies processes that both triggered a security alert and exhibited unusually high CPU utilization
---

This rule provides a mechanism for identifying malicious processes by correlating endpoint security alerts with system-level resource utilization data. By monitoring for processes that trigger security alerts while simultaneously consuming 70% or more of CPU cycles, security teams can distinguish between standard administrative alerts and potentially active threats, such as unauthorized cryptominers or exploit payloads that impose significant system load.

The detection requires the Elastic Agent 'System' integration to collect CPU metrics, which are then evaluated alongside existing security alerts in the Elastic Security index. This higher-order correlation helps reduce the noise associated with isolated security alerts by highlighting processes that are both suspicious and demonstrably active in a way that impacts host performance. The rule includes built-in filters for common high-resource benign processes such as ESET security agents and UiPath compiler tools.

## Impact

Successful attacks involving high-resource abuse can lead to performance degradation of critical business systems, potential exfiltration of credentials during process injection, or unauthorized utilization of cloud compute resources. This detection helps identify these scenarios early, allowing for host isolation before broader compromise or resource exhaustion occurs.

## Recommendation

- Deploy the Elastic Agent with the 'System' integration to all critical endpoints to collect host CPU metrics.
- Enable the 'system.cpu' and 'system.process' datasets in the integration policy to provide the necessary telemetry for high-CPU correlation.
- Utilize the provided detection logic to monitor for processes that concurrently generate a security alert and exceed 70% normalized CPU usage.
- Tune the detection by adding specific organizational baseline software that performs intensive but benign tasks to the exclusion list defined in the rule logic.
- Establish an automated response workflow to isolate hosts identified by this rule for forensic analysis if malicious activity is confirmed.
