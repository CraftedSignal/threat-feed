---
title: Detection of Windows LOLBAS Execution from Unexpected Paths
slug: 2026-10-windows-lolbas-unexpected-path
description: This detection identifies adversary defense evasion via the execution of Living Off the Land Binaries and Scripts (LOLBAS) from non-standard directory locations.
date: "2026-10-05T18:02:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - lolbas
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Adversaries often move or rename system binaries to locations outside of their expected directories (e.g., System32 or Program Files) to avoid detection while executing malicious code.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The LOLBAS project documents Windows native binaries that can be abused by threat actors to perform tasks like executing malicious code.
    confidence_band: high
rules:
  - title: Detect Windows LOLBAS Executed Outside Expected Path
    description: Detects the execution of Windows native binaries from non-standard file paths, which may indicate adversary defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.005
      - T1218.011
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided detection rule to the SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides the logic for detecting LOLBAS execution outside expected paths.
  hunt_leads:
    - lead: Identify all process executions from C:\Users\Public\ and C:\ProgramData\.
      technique_id: T1036
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Adversaries frequently use common writeable paths to stage malicious binaries.
---

This detection analytic identifies instances where Windows native binaries, identified as part of the LOLBAS project, are executed from file paths outside of standard system directories. Adversaries frequently leverage LOLBAS to execute malicious code, perform reconnaissance, or maintain persistence while evading traditional signature-based security controls. By moving or renaming legitimate system utilities to non-standard locations, such as temporary directories or user-profile folders, attackers attempt to bypass path-based blocklists and application allowlisting policies. This analytic specifically monitors process execution telemetry to flag deviations from known-good installation paths, including directories like System32, SysWOW64, and Program Files, providing visibility into potential defense evasion activity.

## Impact

Successful exploitation of LOLBAS binaries allows attackers to blend malicious activity with legitimate system processes, complicating incident response and forensic analysis. Unauthorized execution of these utilities can facilitate lateral movement, privilege escalation, and data exfiltration within an enterprise environment.

## Recommendation

Detection engineering teams should implement the provided Sigma rule to monitor for process executions occurring outside of authorized system paths. It is critical to tune this analytic against the specific environment to establish an allowlist for third-party software or legitimate administrative scripts that may utilize binaries from non-standard locations. Ensure Sysmon Event ID 1 or Windows Event ID 4688 is enabled to capture necessary process path telemetry for this detection.
