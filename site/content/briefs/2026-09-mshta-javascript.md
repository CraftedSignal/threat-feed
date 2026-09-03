---
title: Suspicious JavaScript Execution Via Mshta.EXE
slug: 2026-09-mshta-javascript
description: Detection of attackers using the Windows mshta.exe utility to execute malicious JavaScript code for living-off-the-land stealth execution.
date: "2026-09-03T12:40:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - living-off-the-land
  - stealth
  - windows
  - process-execution
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Detects execution of javascript code using mshta.exe.
    confidence_band: high
rules:
  - title: Detect Suspicious JavaScript Execution Via Mshta.EXE
    description: Detects execution of JavaScript code using mshta.exe, a technique used by attackers for fileless payload delivery.
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Rule defined in brief
  hunt_leads:
    - lead: Search for mshta.exe execution containing 'javascript:' or 'vbscript:' in command lines
      technique_id: T1218.005
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Common pattern for mshta abuse
---

This brief addresses the abuse of mshta.exe, a legitimate Windows utility designed to execute Microsoft HTML Applications (.hta). Attackers leverage this binary to execute arbitrary JavaScript or VBScript via command-line arguments to bypass security controls. By passing script code directly to mshta.exe, malicious actors achieve fileless execution or stage secondary payloads without triggering standard script-based blocklists. This technique is frequently observed in the early stages of post-exploitation to establish persistence or execute initial loader scripts. Defenders should monitor for command-line arguments explicitly invoking JavaScript engines through mshta.exe.

## Impact

Successful abuse of mshta.exe allows attackers to execute code in the context of the current user, potentially facilitating credential harvesting, malware delivery, or lateral movement within an environment.

## Recommendation

Deploy the provided Sigma rule to detect suspicious process creation events involving mshta.exe. Ensure process-level command-line logging is enabled via Sysmon (Event ID 1) or Windows Security Event Logs (Event ID 4688 with command line auditing enabled). Investigate any instances where mshta.exe is launched from non-standard parent processes or contains obfuscated script content.
