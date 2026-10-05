---
title: Detection of Renamed Windows LOLBAS Binaries
slug: 2026-10-renamed-lolbas-execution
description: This detection identifies potential defense evasion by monitoring for native Windows Living Off The Land Binaries (LOLBAS) executing with non-matching original file name metadata.
date: "2026-10-05T18:00:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - endpoint
  - masquerading
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The following analytic identifies a LOLBAS process being executed where it's process name does not match it's original file name attribute.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1036/003/
  - https://redcanary.com/threat-detection-report/techniques/rename-system-utilities/
rules:
  - title: Detect Renamed Windows LOLBAS Binary Execution
    description: Detects execution of a Windows binary where the process name does not match the OriginalFileName attribute, indicating potential masquerading.
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM/EDR environment.
      owner: Detection Engineering
      due: 72h
      evidence: Need to detect renamed LOLBAS execution.
  mitigation_plan:
    - priority: medium_term
      action: Review process creation logs for rename patterns.
      owner: SOC
      addresses: T1036.003
      evidence: Masquerading detection implementation.
---

Adversaries frequently employ masquerading techniques to evade endpoint security controls by renaming legitimate Windows native binaries. By executing these files under different names, attackers attempt to bypass path-based allowlisting or reputation-based detection mechanisms that rely on file name or path attributes. This activity leverages the Living Off The Land Binaries and Scripts (LOLBAS) project, which documents native tools that can be weaponized for malicious purposes, such as command execution, data staging, or lateral movement. Detection of this behavior is critical for identifying post-exploitation activity where legitimate system utilities are repurposed to mask malicious processes. Defenders should focus on comparing the 'OriginalFileName' attribute extracted from the PE header against the actual process name on disk.

## Impact

Successful masquerading can allow an attacker to bypass signature-based defense mechanisms, persist in the environment, and execute unauthorized code under the guise of legitimate system maintenance processes, increasing the dwell time of an undetected intrusion.

## Recommendation

Deploy detection logic to cross-reference process execution logs with file metadata. Enable and ingest Sysmon Event ID 1 or equivalent EDR process-creation telemetry that includes the 'OriginalFileName' attribute.

* Deploy the provided Sigma rule to identify process execution mismatches in your EDR telemetry.
* Tune the detection by creating an allowlist for known third-party software that shares naming conventions with native Windows binaries.
* Use the resulting alerts to investigate parent process chains and command-line arguments to determine the intent of the executed process.
