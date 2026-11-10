---
brief_id: brief-2026-11-10-macos-system-profiler-discovery
event_id: brief-2026-11-10-macos-system-profiler-discovery
revision: 1
activity_at: "2026-11-10T02:40:21Z"
title: 'MacOS: System information discovery via system_profiler'
slug: 2026-11-macos-system-profiler-discovery
description: Threat actors and malware frequently use the system_profiler utility on MacOS to perform system information discovery and identify virtualization for environment checks.
date: "2026-11-10T02:40:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: This process is primarily used for system information discovery.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1497.001
    technique_name: System Checks
    evidence: system_profiler can also be used to determine if virtualization software is being run for defense evasion purposes.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/macos/process_creation/proc_creation_macos_system_profiler_discovery.yml
  - https://www.trendmicro.com/en_za/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html
  - https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
rules:
  - title: Detect System Information Discovery Using System_Profiler
    description: Detects the execution of system_profiler with specific data types often used by malware for system discovery or environment checks.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - stealth
    techniques:
      - T1082
      - T1497.001
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection for system_profiler discovery
      owner: Detection Engineering
      due: 7d
      evidence: Source provided Sigma rule
  hunt_leads:
    - lead: Identify processes running system_profiler with unauthorized arguments
      technique_id: T1082
      data_needed:
        - Process creation logs containing CommandLine
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source documented common data types used by attackers
---

The MacOS command-line utility 'system_profiler' is frequently leveraged by threat actors to perform reconnaissance on host systems. By querying specific data types, attackers can gather detailed hardware and software configuration information, which assists in profiling the victim's environment. Additionally, this utility is used for sandbox detection or identifying virtualization software to support defense evasion.

## Recommendation

Detection engineering teams should monitor for the execution of 'system_profiler' with sensitive flags. Because administrative scripts may legitimately utilize these commands, baseline environment activity to reduce false positives before enabling high-alerting thresholds.

* Deploy the provided Sigma rule to identify unauthorized or suspicious calls to 'system_profiler'.
* Audit scripts and management tools that perform system discovery to establish a baseline of authorized behavior.
