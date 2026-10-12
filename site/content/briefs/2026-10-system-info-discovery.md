---
title: Detection of System Information Discovery Techniques on Windows
slug: 2026-10-system-info-discovery
description: An analytic for identifying system information discovery techniques, including the execution of wmic, systeminfo, and hostname, used by attackers to profile target environments.
date: "2026-10-12T17:59:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - windows
  - edr
  - reconnaissance
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: The following analytic identifies system information discovery techniques, such as the execution of commands like wmic qfe, systeminfo, and hostname.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: The following analytic identifies system information discovery techniques, such as the execution of commands like wmic qfe.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/system_information_discovery_detection.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.yaml
rules:
  - title: Detect System Information Discovery Commands
    description: Detects potential reconnaissance activity by monitoring for the execution of wmic, systeminfo, and hostname commands.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1047
      - T1082
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Implement process-creation logging for the listed binaries
      owner: IT Operations
      due: 48h
      evidence: Analytic requirement for EDR process-creation logs
  hunt_leads:
    - lead: Identify hosts executing multiple unique discovery commands within a short window
      technique_id: T1082
      data_needed:
        - Process creation events
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Analytic thresholds identified in source
  mitigation_plan:
    - priority: medium
      action: Limit execution permissions for non-administrative users for system enumeration binaries
      owner: IT Operations
      addresses: T1082
      evidence: General security best practice for reducing reconnaissance capability
---

This detection analytic identifies common system information discovery techniques utilized by threat actors to map a compromised Windows environment. By monitoring process execution logs from EDR or Sysmon, the analytic triggers when a user or process executes multiple enumeration commands within a short window - specifically targeting `wmic qfe`, `systeminfo`, and `hostname`. 

These commands are frequently abused by attackers during the early stages of an intrusion to collect data regarding patches, system configuration, and network identity. Such reconnaissance allows adversaries to refine their exploitation path, determine target privilege levels, and tailor their persistence or exfiltration strategies. The analytic is designed to reduce noise by requiring a threshold of more than two unique discovery commands per host, which effectively separates malicious reconnaissance activity from legitimate administrative debugging or maintenance.

## Impact

Successful system discovery provides attackers with actionable intelligence on the target host, directly enabling follow-on post-exploitation activities such as privilege escalation, lateral movement, or targeted data exfiltration. This behavior has been observed across a wide array of threat groups, including those deploying ransomware like BlackSuit and Medusa, and stealer malware such as BlankGrabber, which leverage this data to customize their operational impact.

## Recommendation

Prioritize the implementation of process-creation logging across all Windows endpoints to ensure the necessary telemetry is available for the detection analytic.

- Enable Sysmon (Event ID 1) or Windows Security Event Logs (Event ID 4688) to capture detailed command-line arguments.
- Map your EDR process-creation logs to the Endpoint data model within your SIEM using the Common Information Model (CIM) to enable the analytic logic.
- Deploy the provided detection logic and tune the `dc(process)` threshold as needed to minimize false positives from administrative activity.
- Integrate the drilldown searches to correlate this discovery activity with historical risk events for the target host to assess whether the discovery is part of a broader, ongoing compromise.
