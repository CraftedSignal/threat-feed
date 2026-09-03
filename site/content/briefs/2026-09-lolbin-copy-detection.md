---
title: Detection of LOLBin Relocation Techniques
slug: 2026-09-lolbin-copy-detection
description: Adversaries frequently copy Living-off-the-Land Binaries (LOLBins) from protected system directories to arbitrary locations to evade security controls that rely on path-based allowlisting.
date: "2026-09-03T12:44:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - persistence
  - lolbin
  - windows
  - detection-engineering
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Detects a suspicious copy operation that tries to copy a known LOLBIN from system directories to another on disk in order to bypass detections based on locations.
    confidence_band: high
rules:
  - title: Detect LOLBin Copied From System Directory
    description: Detects a suspicious copy operation that attempts to copy a known LOLBin from protected system directories (System32, SysWOW64, WinSxS) to another location to evade path-based detections.
    platform: sigma
    severity: medium
    tactics:
      - stealth
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
    - action: Deploy the Sigma rule to monitor for suspicious binary relocation.
      owner: Detection Engineering
      due: 72h
      evidence: Rule provided in brief.
  hunt_leads:
    - lead: Search process creation logs for 'copy', 'move', or 'cp' commands involving directories like System32, SysWOW64, or WinSxS.
      technique_id: T1036
      data_needed:
        - Process creation telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: General behavior described in Sigma documentation.
---

Threat actors often leverage native Windows binaries (LOLBins) to execute malicious code while blending into legitimate system activity. Defenders commonly use path-based allowlisting or monitoring to detect unauthorized execution of tools like `certutil.exe` or `rundll32.exe`. To bypass these defenses, attackers execute copy operations - using native utilities like `cmd.exe`, `powershell.exe`, or `robocopy.exe` - to move these binaries from protected system directories such as `System32`, `SysWOW64`, or `WinSxS` to non-standard, user-writable locations. By executing the relocated binary, the attacker avoids alerts triggered by execution from privileged system paths. This behavior is a common precursor to malware delivery and execution, as observed in various documented attacks, including HTML smuggling and ransomware campaigns. Monitoring for the relocation of specific dual-use binaries is critical for identifying lateral movement and persistence attempts.

## Impact

Successful relocation of LOLBins allows attackers to maintain stealth during the execution of malicious payloads, potentially bypassing endpoint security policies. This technique facilitates further compromise, including credential theft, lateral movement, or the deployment of ransomware within a target environment.

## Recommendation

* Deploy the provided Sigma rule to detect the movement of dual-use binaries from protected system directories.
* Tune the detection to account for administrative scripts or deployment tools that may legitimately move binaries, though such activity should generally be audited.
* Audit file creation events in sensitive directories to correlate copy operations with subsequent execution patterns.
