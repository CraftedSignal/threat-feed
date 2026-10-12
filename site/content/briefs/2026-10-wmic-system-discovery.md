---
title: Detection of WMIC System Information Discovery
slug: 2026-10-wmic-system-discovery
description: This brief documents the use of Windows Management Instrumentation Command-line (WMIC) for reconnaissance, specifically focusing on the 'wmic computersystem' command used by adversaries to profile system environments.
date: "2026-10-12T18:25:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - windows
  - reconnaissance
  - wmic
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: The following analytic detects the execution of Windows Management Instrumentation Command-line (WMIC) commands used for computer system discovery.
    confidence_band: high
references:
  - https://cert.gov.ua/article/6284730
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1082/T1082.yaml#L381
rules:
  - title: Detect WMIC Computer System Discovery
    description: Detects the use of WMIC to query computersystem information, which may indicate reconnaissance activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for WMIC computer system queries.
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic confirms WMIC usage for reconnaissance.
  hunt_leads:
    - lead: Search for historical execution of 'wmic computersystem' in process logs to establish a baseline of administrative activity.
      technique_id: T1082
      data_needed:
        - Process creation telemetry
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Baseline establishment reduces false positives.
  mitigation_plan:
    - priority: medium
      action: Implement strict auditing of administrative tools and limit WMIC access to authorized service accounts.
      owner: IT Operations
      addresses: T1082
      evidence: Standard hardening practice for administrative utilities.
---

Adversaries frequently employ built-in Windows utilities to conduct reconnaissance during the initial stages of a compromise. The Windows Management Instrumentation Command-line (WMIC) utility is often abused to gather detailed information about a target endpoint, including hardware model, manufacturer, domain membership, and system naming conventions. 

This activity is identified through the execution of the command "wmic computersystem," which returns comprehensive system attributes. While this functionality is a standard administrative tool for system inventory and troubleshooting, its execution by non-administrative processes or users - or in suspicious parent-child process chains - is a key indicator of attacker profiling. This detection is applicable to environments where visibility into process creation, including complete command-line arguments, is available. Security teams should monitor for this behavior to detect unauthorized information gathering activities commonly seen in campaigns involving malwares like LAMEHUG, BlankGrabber, and the Lotus Blossom Chrysalis backdoor.

## Impact

The abuse of system discovery tools allows adversaries to gain critical situational awareness, enabling them to tailor subsequent lateral movement, privilege escalation, or malware deployment strategies to the specific target environment. If left undetected, this reconnaissance phase allows attackers to refine their payloads and increase the likelihood of a successful long-term infiltration or data exfiltration effort.

## Recommendation

Prioritize the detection of system discovery activities by monitoring process execution telemetry.

- Deploy the Sigma rule provided in this brief to identify potential unauthorized use of WMIC for system profiling.
- Ensure EDR agents or Sysmon (Event ID 1) are configured to log the full command-line arguments and parent process information to enable effective detection.
- Review and tune the detection in environments where automated inventory or management scripts frequently invoke "wmic computersystem."
