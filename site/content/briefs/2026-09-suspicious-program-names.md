---
title: Detection of Suspicious Artifacts and Tools via File Names
slug: 2026-09-suspicious-program-names
description: This brief documents patterns in file naming conventions frequently associated with attacker toolkits, proof-of-concept exploits, and red team frameworks.
date: "2026-09-03T12:45:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - detection
  - offensive-tooling
  - monitoring
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The rule identifies usage of PowerShell scripts with suspicious naming conventions associated with common offensive frameworks.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_progname.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
rules:
  - title: Detect Suspicious Program Names and Paths
    description: Detects suspicious patterns in program names or folders that are often found in malicious samples, PoCs, or hacktools.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
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
    - action: Deploy Sigma detection rule to environment.
      owner: Detection Engineering
      due: 72h
      evidence: Rule presence in standard security monitoring libraries.
  hunt_leads:
    - lead: Search for historical process creation events matching the listed suspicious file names in the rule.
      technique_id: T1059
      data_needed:
        - Process creation logs (Image, CommandLine)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source provides list of common artifacts.
---

Defenders frequently encounter indicators of adversary activity where tools, payloads, or exploit scripts utilize predictable, default, or descriptive file names. These patterns often arise from the use of publicly available offensive security frameworks, proof-of-concept (PoC) code released in security advisories, or common testing artifacts used during red team engagements. By monitoring for specific file paths and naming conventions, security teams can detect the presence of staging, execution, or testing activities that deviate from standard environment behavior. This detection logic focuses on common naming patterns, such as references to CVE identifiers, various iterations of 'artifact' binaries, and script filenames suggestive of offensive capabilities like beaconing, shellcode execution, or credential dumping.

## Impact

Successful identification of these artifacts allows security operations teams to detect early-stage attacker staging or unauthorized red team activity. If left unmonitored, these predictable naming conventions provide a simple indicator that an actor is utilizing standardized tooling, potentially indicating a higher likelihood of automated or template-driven exploitation attempts.

## Recommendation

Deploy detection coverage for process creation events to identify the execution of files matching common offensive naming conventions. Prioritize tuning these rules based on internal legitimate development and security testing activities.

- Deploy the provided Sigma rule to identify common offensive tool and artifact naming conventions within the environment.
- Baseline existing automated maintenance scripts and administrative tools to ensure they do not trigger these detection patterns.
- Integrate these detection rules with Sysmon Event ID 1 (Process Creation) logs to capture the full command line and image path for forensic analysis.
