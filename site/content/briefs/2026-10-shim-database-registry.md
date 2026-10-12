---
title: Registry Activity Associated with Windows Application Compatibility Shims
slug: 2026-10-shim-database-registry
description: Adversaries can abuse the Windows Application Compatibility Shim (AppCompatFlags) mechanism by modifying specific registry keys to achieve persistence, escalate privileges, or bypass security controls.
date: "2026-10-12T17:55:39Z"
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
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.011
    technique_name: 'Event Triggered Execution: Application Shimming'
    evidence: Attackers can use shims to bypass security controls, achieve persistence, or escalate privileges.
    confidence_band: high
rules:
  - title: Detect Registry Keys for Creating Shim Databases
    description: Detects registry writes to AppCompatFlags Custom or InstalledSDB keys which may indicate shim database installation for persistence
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
    - action: Deploy the Sigma rule to monitor AppCompatFlags registry activity
      owner: Detection Engineering
      due: 48h
      evidence: Source explicitly identifies registry modification as the detection target
  hunt_leads:
    - lead: Audit existing installed shim databases
      technique_id: T1546.011
      data_needed:
        - Registry data and sdbinst list output
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Shim databases are a persistent threat technique
  mitigation_plan:
    - priority: medium_term
      action: Restrict registry write access to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags
      owner: IT Operations
      addresses: T1546.011
      evidence: Registry modification is required for this technique
---

Windows Application Compatibility Shims are designed to allow legacy applications to function on newer versions of the operating system by intercepting API calls and redirecting them. Threat actors frequently abuse this architectural feature as a persistence or privilege escalation mechanism. By modifying registry keys under 'AppCompatFlags\Custom' or 'AppCompatFlags\InstalledSDB', an attacker can force the operating system to load a malicious Shim Database (SDB) file whenever specific applications are executed. Because these shims can execute arbitrary code within the context of the hooked application, this technique allows for stealthy execution, security control bypasses, and long-term access. Defenders must monitor registry modification events targeting these specific paths to identify unauthorized shim database installation or configuration changes.

## Attack Chain

1. Attacker gains initial access to the Windows system.
2. Attacker develops or obtains a malicious Shim Database (SDB) file designed to hook a target application.
3. Attacker uses a tool like 'sdbinst.exe' or direct registry manipulation to register the malicious SDB.
4. Attacker writes registry values to 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom' or 'InstalledSDB' to point to the malicious shim.
5. The target application is launched by a user or an automated service.
6. The Windows Shim Engine detects the registration and loads the malicious SDB into the target process memory.
7. The malicious code within the shim executes, providing the attacker with persistent access or elevated privileges.

## Impact

Successful exploitation allows attackers to maintain stealthy persistence, escalate privileges by hooking sensitive processes, and bypass various application-level security controls. This technique is highly effective for long-term presence on compromised endpoints and can lead to full system compromise if hooks are placed in privileged administrative tools or security software.

## Recommendation

1. Deploy the provided Sigma rule to monitor for registry writes in 'AppCompatFlags' paths to identify suspicious installation or modification of shim databases.
2. Enable Sysmon Event ID 13 (RegistryEvent) across all endpoints to ensure the required telemetry for registry modification monitoring is available.
3. Perform threat hunting for modifications in 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags' to detect unauthorized activity.
4. Audit the system for existing, unexpected shim databases using tools such as 'sdbinst.exe /list' to identify potential persistent threats.
