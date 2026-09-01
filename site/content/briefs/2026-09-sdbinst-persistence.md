---
title: Shim Database Persistence via Sdbinst.EXE
slug: 2026-09-sdbinst-persistence
description: Adversaries may use the legitimate Windows sdbinst.exe binary to install malicious application shim databases for the purpose of maintaining persistence or escalating privileges.
date: "2026-09-01T12:24:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims
    confidence_band: high
references:
  - https://www.mandiant.com/resources/blog/fin7-shim-databases-persistence
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_sdbinst_shim_persistence.yml
rules:
  - title: Detect Potential Shim Database Persistence via Sdbinst.EXE
    description: Detects the installation of a new application shim database using sdbinst.exe, a technique used for persistence and privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.011
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to environment
      owner: Detection Engineering
      due: 48h
      evidence: Source provides concrete detection logic for this TTP
  hunt_leads:
    - lead: Search for all instances of sdbinst.exe process execution over the last 90 days
      technique_id: T1546.011
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: This technique is a known persistence mechanism for actors like FIN7
  mitigation_plan:
    - priority: medium
      action: Implement application control policies to restrict sdbinst.exe execution to known, trusted paths and processes
      owner: IT Operations
      addresses: T1546.011
      evidence: Restricting execution environment is a standard mitigation for binary abuse
---

Attackers may abuse the Windows Application Compatibility Infrastructure to establish persistence or perform privilege escalation. By creating a custom Application Compatibility Database (.sdb file) containing malicious instructions or code and installing it using the legitimate system binary sdbinst.exe, an attacker can cause the malicious shim to be loaded when specific target applications execute. This technique allows code execution with the permissions of the targeted process, which can lead to privilege escalation if the target is a high-privileged service or application. Defenders should monitor for the execution of sdbinst.exe, especially when invoked with parameters referencing .sdb files, as this is a rare event in well-managed enterprise environments.

## Attack Chain

1. Attacker crafts a malicious Application Compatibility Database (.sdb) file.
2. Attacker gains initial access or code execution on the target Windows system.
3. Attacker identifies a legitimate application to target for shim injection.
4. Attacker writes the .sdb file to a directory on the disk (e.g., C:\ProgramData\).
5. Attacker executes sdbinst.exe via command line to install the shim database: sdbinst.exe &lt;path_to_malicious_file>.sdb.
6. The system registers the shim database, causing it to load when the target application starts.
7. The target application is launched by a user or service.
8. The malicious code within the shim is executed, granting the attacker persistence or elevated privileges.

## Impact

Successful exploitation allows for stealthy persistence that is not easily removed by standard antimalware solutions. It enables attackers to elevate privileges by injecting code into high-integrity processes, potentially granting full system control depending on the targeted application.

## Recommendation

Deploy the provided Sigma rule to detect the installation of new shim databases. Monitor process creation events for sdbinst.exe activity and investigate the command line parameters to identify the .sdb file path. Maintain an inventory of legitimate shim database installations to facilitate exclusion tuning.

- Enable Sysmon or Windows Event Log (Event ID 4688) process-creation logging.
- Deploy the Sigma rule below to the SIEM and tune for legitimate application updates or installation scripts.
- Audit existing shim databases on critical infrastructure to ensure no unauthorized persistence mechanisms are present.
