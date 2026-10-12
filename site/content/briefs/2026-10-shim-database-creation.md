---
title: Detection of Malicious Shim Database (.sdb) File Creation
slug: 2026-10-shim-database-creation
description: Attackers can use Application Compatibility Database (.sdb) files to intercept API calls, allowing for privilege escalation and persistence by bypassing Windows security controls.
date: "2026-10-12T17:58:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: The analytic detects the creation of shim database files (.sdb) which are used to intercept and alter API calls, potentially allowing attackers to bypass security controls.
    confidence_band: high
rules:
  - title: Detect Shim Database (.sdb) File Creation
    description: Detects the creation of shim database files (.sdb) in the Windows AppPatch Custom directory, which may indicate the installation of malicious shim databases.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1546.011
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for .sdb file creation in AppPatch\Custom
      owner: Detection Engineering
      due: 48h
      evidence: Detection engineering requirement for T1546.011
  hunt_leads:
    - lead: Search for existing .sdb files in C:\Windows\AppPatch\Custom\ that have been modified recently
      technique_id: T1546.011
      data_needed:
        - Filesystem telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Standard location for shim databases
  mitigation_plan:
    - priority: medium
      action: Review and audit all installed shim databases using sdbinst.exe /query
      owner: IT Operations
      addresses: T1546.011
      evidence: System utility for managing shim databases
---

Windows Application Compatibility shims are a legitimate mechanism used to ensure older applications run correctly on newer versions of the operating system by intercepting and redirecting API calls. However, this functionality is frequently abused by attackers to gain persistence or elevate privileges. By creating a custom shim database (.sdb) and installing it via the `sdbinst.exe` utility, an attacker can force the operating system to load malicious code into processes or bypass security checks. This detection focuses on monitoring filesystem writes to the `%SystemRoot%\AppPatch\Custom` directory, which is the standard location for user-defined shim databases. While legitimate administrative activity can occur here, unexpected file creation in this directory is a high-fidelity signal for security operations teams to investigate potential unauthorized persistence mechanisms.

## Attack Chain

1. Attacker gains local administrative access to the target Windows system.
2. Attacker crafts a malicious Shim Database (.sdb) file containing redefined API hooks.
3. Attacker uses `sdbinst.exe` to register the malicious .sdb file within the system.
4. The malicious shim database is written to the `%SystemRoot%\AppPatch\Custom` directory.
5. The OS loads the shim database during process execution or system boot, depending on the scope of the shim.
6. API calls made by targeted applications or processes are redirected to the attacker-supplied malicious code.
7. Attacker achieves persistence or privilege escalation through the executed code.

## Impact

Successful abuse of the shim mechanism can lead to persistent code execution and privilege escalation, as the malicious code is loaded by legitimate processes. This allows attackers to hide activities, bypass security software, and maintain long-term access to compromised environments.

## Recommendation

1. Enable Sysmon Event ID 11 (FileCreate) to capture filesystem modifications.
2. Deploy the provided Sigma rule to detect file writes in the specified AppPatch directory.
3. Investigate any file creations in `C:\Windows\AppPatch\Custom\` that lack a clear association with authorized software installation or maintenance.
4. Monitor for executions of `sdbinst.exe` associated with the creation of new .sdb files.
