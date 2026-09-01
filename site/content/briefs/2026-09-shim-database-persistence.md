---
title: Windows Application Shim Database Persistence
slug: 2026-09-shim-database-persistence
description: Adversaries can achieve persistence and privilege escalation by installing malicious shim databases to intercept and redirect application execution.
date: "2026-09-01T12:13:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - registry
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546.011
    technique_name: Application Shim
    evidence: Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.011
    technique_name: Application Shim
    evidence: Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims.
    confidence_band: high
rules:
  - title: Detect Shim Database Registry Modification
    description: Detects modifications to the Windows AppCompatFlags registry keys which may indicate the installation of a persistent malicious shim database.
    platform: sigma
    severity: medium
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
    - action: Deploy the shim registry monitoring rule to identify active SDB registration attempts.
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in the briefing.
  hunt_leads:
    - lead: Registry modifications in HKLM/HKCU AppCompatFlags
      technique_id: T1546.011
      data_needed:
        - Registry auditing event logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Registry-based persistence technique documentation.
---

The Windows Application Compatibility Infrastructure, commonly referred to as Application Shimming, is a mechanism designed to allow legacy software to function on newer versions of the Windows operating system. Adversaries leverage this framework to achieve persistence or escalate privileges by installing a custom, malicious shim database (SDB file). When the shim is active, the operating system loads the malicious library or triggers the defined behavior whenever the targeted application is executed. This technique is well-documented in historical campaigns, such as those attributed to FIN7, which utilized shim databases to ensure long-term, stealthy access. Defenders must monitor modifications to the Application Compatibility registry keys to identify the unauthorized deployment of shim databases within their environment.

## Attack Chain

1. Attacker prepares a malicious SDB file designed to trigger a specific payload or hook a targeted application.
2. Attacker gains administrative access to the target host through secondary exploitation.
3. Attacker uses the Windows `sdbinst.exe` utility to install the custom shim database.
4. The installation process creates or modifies registry entries under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\` or `Custom\`.
5. The attacker targets a commonly used application that will load the malicious shim upon startup.
6. The targeted application is executed, causing the shim engine to process the malicious database.
7. The shim engine executes the attacker's payload within the context of the hooked application, achieving persistence or privilege escalation.

## Impact

Successful exploitation allows an adversary to maintain persistent, stealthy access to the system. By hooking legitimate processes, the attacker can hide malicious activity within the memory space of trusted applications, potentially evading traditional security monitoring. This persistence mechanism is robust, as it survives system reboots and is triggered by the natural usage of hooked applications.

## Recommendation

1. Deploy the provided Sigma rule to monitor registry modifications within the `AppCompatFlags` path to detect unauthorized SDB installations.
2. Baseline your environment to identify legitimate custom shim databases and filter those from the detection logic to reduce noise.
3. Restrict execution of `sdbinst.exe` to authorized administrative accounts and perform regular audits of installed shim databases using the `sdbinst -q` command.
