---
brief_id: brief-2026-11-10-shim-database-patching
event_id: brief-2026-11-10-shim-database-patching
revision: 1
activity_at: "2026-11-10T03:09:39Z"
title: Suspicious Shim Database Installation
slug: 2026-11-shim-database-patching
description: Adversaries, including the threat actor FIN7, have been observed using the Application Compatibility Shim database to achieve persistence and facilitate process injection by patching sensitive system binaries.
date: "2026-11-10T03:09:39Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - FIN7
  - Carbon Spider
  - Sangria Tempest
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: verified against sigma-hq rule structure
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546.011
    technique_name: Application Shimming
    evidence: Detects installation of new shim databases that try to patch sections of known processes for potential process injection or persistence.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.011
    technique_name: Application Shimming
    evidence: Detects installation of new shim databases that try to patch sections of known processes for potential process injection or persistence.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_shim_database_susp_application.yml
  - https://www.levelblue.com/blogs/spiderlabs-blog/pillowmint-fin7s-monkey-thief/
  - https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
rules:
  - title: Detect Suspicious Shim Database Patching
    description: Detects the installation of a new Shim Database targeting core Windows system processes, a technique associated with persistence and process injection.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.011
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Shim Database registry monitoring rule to production SIEM
      owner: Detection Engineering
      due: 24h
      evidence: SigmaHQ rule bf344fea-d947-4ef4-9192-34d008315d3a
  hunt_leads:
    - lead: Identify all shim databases installed on critical workstations
      technique_id: T1546.011
      data_needed:
        - 'Command line execution: sdbinst.exe -l'
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Shim databases are registered using sdbinst.exe
  mitigation_plan:
    - priority: medium
      action: Implement application control or restriction policies to prevent sdbinst.exe execution by non-privileged users
      owner: IT Operations
      addresses: T1546.011
      evidence: Shim installation utility abuse
---

The Application Compatibility Shim infrastructure can be abused to inject code or maintain persistence by hooking system binaries. Actors modify the registry under the `AppCompatFlags` path to force the Windows Compatibility Manager to load malicious shim databases (.sdb files) when specific system processes are executed.

## Attack Chain

1. Attacker crafts a malicious Shim Database (.sdb) file.
2. Attacker installs the shim database using the `sdbinst.exe` utility.
3. The shim database installation registers the malicious DLL in the Windows Registry under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\`.
4. The Windows Compatibility Manager detects the Shim registry entry for the targeted system process.
5. Upon process execution, the Shim engine injects the defined hooks or patches into the target process memory space.
6. Malicious code is executed within the context of the target system process.

## Recommendation

- Deploy the provided Sigma rule to monitor registry modifications within the `AppCompatFlags\Custom` subkeys.
- Audit existing installed Shim Databases using the `sdbinst.exe -q -l` command to identify unauthorized or unknown databases.
- Restrict the ability to install new Shim Databases to authorized administrative accounts and known-good software deployment tools.
