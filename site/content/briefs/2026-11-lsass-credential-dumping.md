---
brief_id: brief-2026-11-10-lsass-credential-dumping
event_id: brief-2026-11-10-lsass-credential-dumping
revision: 1
activity_at: "2026-11-10T02:47:29Z"
title: Credential Dumping via LSASS Process Access
slug: 2026-11-lsass-credential-dumping
description: Multiple credential dumping tools, including Mimikatz, NanoDump, and Procdump, perform unauthorized memory access against the Local Security Authority Subsystem Service (LSASS) process to extract sensitive credentials.
date: "2026-11-10T02:47:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - credential-access
  - windows
  - lsass
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.001
    technique_name: LSASS Memory
    evidence: Detects process access requests to the LSASS process with specific call trace calls and access masks.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_lsass_memdump.yml
  - https://web.archive.org/web/20230329170326/https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html
  - https://research.splunk.com/endpoint/e4723b92-7266-11ec-af45-acde48001122/
rules:
  - title: Detect Potential LSASS Credential Dumping
    description: Detects suspicious access requests to lsass.exe by common credential dumping tools using specific access masks and call traces associated with memory dumping functions.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_access
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Sysmon Event ID 10 to monitor LSASS process access
      owner: IT Operations
      due: 48h
      evidence: LSASS process dumping requires process access telemetry to detect.
  hunt_leads:
    - lead: Hunt for processes accessing lsass.exe with high-privilege access masks
      technique_id: T1003.001
      data_needed:
        - Sysmon Event ID 10
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Many credential dumping tools access LSASS to read memory.
---

Credential dumping tools frequently target the Windows LSASS process to extract plaintext passwords, NTLM hashes, or Kerberos tickets from memory. This activity typically involves opening a handle to lsass.exe with specific access masks to read memory segments, often utilizing legitimate system libraries like dbghelp.dll or dbgcore.dll. This behavior is commonly observed in tools such as Mimikatz, NanoDump, Invoke-Mimikatz, and Procdump, as well as the native Task Manager "Create dump file" feature.

## Impact

Successful credential dumping allows attackers to harvest credentials from memory, facilitating lateral movement, privilege escalation, and persistence within the environment.

## Recommendation

* Deploy the detection rule below to identify suspicious handles being requested for the LSASS process.
* Baseline legitimate administrative activity or security tooling that may trigger this rule, such as legitimate memory diagnostics or authorized security scanners, to tune out false positives.
* Enable Sysmon process access logging (Event ID 10) to capture the necessary GrantedAccess and CallTrace telemetry.
