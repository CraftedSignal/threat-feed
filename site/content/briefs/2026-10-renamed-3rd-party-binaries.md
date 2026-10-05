---
title: Detection of Masquerading via Renamed Third-Party Binaries
slug: 2026-10-renamed-3rd-party-binaries
description: This analytic identifies potential defense evasion activity by detecting instances where common third-party software binaries are executed under a filename that does not match their original file name metadata.
date: "2026-10-05T18:01:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - masquerading
  - endpoint
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The following analytic identifies a popular 3rd party software process being executed where it's process name does not match it's original file name attribute.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1036/
  - https://attack.mitre.org/techniques/T1036/003/
  - https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
  - https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/
rules:
  - title: Detect Renamed Third-Party Software Execution
    description: Detects the execution of known third-party binaries where the process name does not match the original file name metadata, a common indicator of masquerading.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to identify renamed third-party binaries
      owner: Detection Engineering
      due: 72h
      evidence: Source provides logic for detecting renamed third-party binaries
  hunt_leads:
    - lead: Identify processes with mismatched OriginalFileName in audit logs
      technique_id: T1036.003
      data_needed:
        - Process creation events with OriginalFileName metadata
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Analytic identifies renaming as a defense evasion technique
---

Adversaries often rename legitimate binaries to masquerade as other files and evade security controls or file-based detection mechanisms. This analytic identifies a popular 3rd party software process being executed where the process name does not match its original file name attribute. This technique is frequently observed in post-exploitation scenarios, including ransomware distribution, where attackers attempt to blend malicious execution with legitimate activity or bypass simple allowlisting rules. Defenders should focus on telemetry that captures both the process name and the internal original file name metadata, typically available through Sysmon Event ID 1 or EDR-specific process events.

## Impact

Successful masquerading via renaming can lead to unauthorized execution of tools, persistence mechanisms, or malicious payloads while evading signature-based security detections. This technique is commonly associated with broader adversary campaigns, including those involving ransomware like LockBit, where renaming binaries assists in initial deployment and execution on victim machines.

## Recommendation

Deploy detection logic to identify mismatches between process execution names and internal binary metadata. Ensure that endpoint telemetry is properly mapped to the Endpoint data model within your SIEM. Tune the detection by creating an allowlist for any known legitimate organizational software that may use unconventional naming conventions.

- Enable Sysmon Event ID 1 (Process Creation) to capture the OriginalFileName field.
- Implement the detection logic below to identify renaming discrepancies.
- Investigate high-risk alerts using the provided drilldown links to analyze risk object associations over the previous 7 days.
- Monitor for activity associated with the 'Living Off The Land' analytic story.
