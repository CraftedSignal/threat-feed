---
title: Detection of Process Injection via Sysmon EventID 10
slug: 2026-09-windows-process-injection
description: Detection of malicious process injection attempts into common Windows executables observed in frameworks like SliverC2 using suspicious access masks in Sysmon EventID 10 logs.
date: "2026-09-21T19:10:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - process-injection
  - defense-evasion
  - privilege-escalation
  - sysmon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
    evidence: The following analytic detects potential process injection attempts into executables that are commonly abused leveraging Sysmon EventCode 10.
    confidence_band: high
rules:
  - title: Detect Suspicious Process Injection via Access Mask
    description: Detects process injection attempts where a non-system process requests high-privilege access masks (PROCESS_DUP_HANDLE or PROCESS_ALL_ACCESS) to commonly abused Windows executables.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1055.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for process access events from non-standard paths.
      owner: Detection Engineering
      due: 48h
      evidence: Source detection logic.
  hunt_leads:
    - lead: Analyze Sysmon EventID 10 logs for granted access masks of 0x40 and 0x1fffff from user-writeable directories.
      technique_id: T1055.002
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic description of injection patterns.
---

This threat brief focuses on detecting process injection techniques targeting common Windows executables, such as notepad.exe, calc.exe, and spoolsv.exe. This activity is commonly employed by adversarial frameworks, specifically the SliverC2 framework by BishopFox, to facilitate payload execution, defense evasion, and privilege escalation. Defenders should monitor for processes originating outside standard system directories (System32, SysWOW64, and Program Files) that request high-privilege access masks (0x40, 0x1fffff) against these target processes using Sysmon EventID 10. By identifying these unauthorized handle duplication or full process access requests, security teams can detect initial payload execution or lateral movement attempts before deeper system compromise occurs.

## Attack Chain

1. Attacker executes an initial payload on the target endpoint.
2. The malicious process locates a benign target process, such as notepad.exe or calc.exe.
3. The attacker requests a process handle with specific high-privilege access masks (0x40 or 0x1fffff) via the Windows API.
4. Sysmon EventID 10 logs the `OpenProcess` event, capturing both the SourceImage and TargetImage.
5. The attacker injects malicious code or duplicates handles into the target process memory space.
6. The target process executes the injected malicious code, effectively hiding the activity within a trusted process.
7. The attacker establishes persistent C2 communication or escalates privileges from the context of the abused process.

## Impact

Successful process injection allows attackers to bypass endpoint security controls, maintain persistence, and execute arbitrary code in the context of trusted applications. This activity has been observed in various campaigns, including those targeting SAP NetWeaver environments and operations associated with APT37, leading to potential data exfiltration and credential theft.

## Recommendation

1. Enable Sysmon logging, ensuring EventID 10 (ProcessAccess) is captured for all critical endpoints.
2. Deploy the provided Sigma rule to your SIEM to flag potential injection attempts where the SourceImage is not located in standard Windows directories.
3. Investigate alerts by reviewing the SourceImage path and the CallTrace field to identify potentially unauthorized modules loading into common processes.
4. Tune the detection by creating an allowlist for known, legitimate internal management tools that may legitimately perform handle duplication on system processes.
