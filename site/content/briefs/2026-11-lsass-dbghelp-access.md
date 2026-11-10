---
brief_id: brief-2026-11-10-lsass-dbghelp-access
event_id: brief-2026-11-10-lsass-dbghelp-access
revision: 1
activity_at: "2026-11-10T03:39:20Z"
title: Suspicious Process Access to LSASS Memory via Dbgcore/Dbghelp
slug: 2026-11-lsass-dbghelp-access
description: Adversaries may use dbgcore.dll and dbghelp.dll, specifically functions like MiniDumpWriteDump, to perform credential dumping from LSASS memory.
date: "2026-11-10T03:39:20Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - credential-access
  - defense-impairment
  - windows
  - lsass
  - process-access
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.001
    technique_name: LSASS Memory
    evidence: These DLLs contain functions like MiniDumpWriteDump that can be abused for credential dumping purposes.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_access/proc_access_win_susp_dbgcore_dbghelp_load.yml
  - https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html
  - https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump
rules:
  - title: Detect Suspicious LSASS Access via Dbgcore or Dbghelp
    description: Detects suspicious access to LSASS.exe by processes running from uncommon paths that load dbgcore.dll or dbghelp.dll into their call trace.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - defense-impairment
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
    - action: Deploy the provided Sigma rule for process access to LSASS.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides detection logic for suspicious LSASS access.
  hunt_leads:
    - lead: Identify all processes executing from user-writable directories (e.g. \Temp\) that have an open handle to LSASS.
      technique_id: T1003.001
      data_needed:
        - Sysmon Event ID 10
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source lists common attack paths for credential dumping utilities.
---

Security research identifies that legitimate Windows debugging DLLs, specifically dbgcore.dll and dbghelp.dll, are frequently abused by offensive tools to facilitate credential dumping from the Local Security Authority Subsystem Service (LSASS). The MiniDumpWriteDump function, while intended for troubleshooting, allows attackers to create memory dumps of processes including LSASS. Tools executing from unconventional locations often leverage these libraries to bypass basic detection mechanisms.

## Impact

Successful abuse of these libraries allows for the acquisition of LSASS process memory, which can be parsed offline to extract credentials, hashes, and cleartext passwords, leading to account takeover and lateral movement.

## Recommendation

- Implement the provided detection rule for LSASS process access initiated from non-standard directories.
- Baseline administrative or debugging tools in the environment that legitimately access LSASS using these DLLs to minimize false positives.
- Review and restrict write/execute permissions in user-accessible directories like C:\Users\Public\ and C:\Windows\Temp\ to impede the execution of credential dumping utilities.
