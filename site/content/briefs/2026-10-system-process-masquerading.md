---
title: Detection of Masquerading via System Processes in Non-Standard Paths
slug: 2026-10-system-process-masquerading
description: This brief addresses the detection of Windows system processes executing from unexpected file paths, a technique frequently used by threat actors for masquerading and defense evasion.
date: "2026-10-05T12:13:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - masquerading
  - windows
  - endpoint-security
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The analytic identifies system processes running from unexpected locations outside of paths such as C:\Windows\System32\ or C:\Windows\SysWOW64.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1036/003/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.yaml
rules:
  - title: Detect System Processes Running From Unexpected Locations
    description: Detects system processes such as svchost.exe or lsass.exe executing from paths other than Windows System32 or SysWOW64.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
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
    - action: Deploy Sigma detection rule to SIEM/EDR platform.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic identifies system processes running from unexpected locations.
  mitigation_plan:
    - priority: short_term
      action: Review process execution logs for common installation paths of third-party software and update exclusion filters.
      owner: SOC
      addresses: False positives in masquerading detection
      evidence: Known false positives note in source content.
---

This threat brief focuses on the detection of Windows system processes that execute from non-standard directory paths. Attackers often utilize masquerading techniques by renaming malicious files to match legitimate system processes or moving them to unconventional directories to evade signature-based security controls. This activity is a common indicator of defense evasion, where adversaries attempt to blend malicious execution with legitimate system background tasks to bypass detection, gain persistent access, or facilitate privilege escalation. This analytic is designed for deployment within EDR platforms to monitor process execution paths against known legitimate Windows directory structures.

## Attack Chain

1. Attacker identifies a target environment and selects a legitimate system process name (e.g., svchost.exe, lsass.exe) to impersonate.
2. Attacker prepares a malicious binary or a copy of a system utility with the chosen name.
3. Attacker drops the file into a non-standard directory, such as a user-controlled folder or temporary directory, to avoid alerting file integrity monitors that watch System32.
4. Attacker modifies permissions or registry keys (e.g., Run keys or Service configurations) to ensure the masqueraded process executes.
5. The system process executes from the unexpected location upon system startup or trigger condition.
6. Attacker leverages the masqueraded process context to execute malicious code, perform credential dumping, or establish command-and-control communication.

## Impact

Successful masquerading can lead to persistent unauthorized access, privilege escalation, and execution of malicious payloads while remaining hidden from basic security monitoring. If an attacker successfully masquerades as a critical system process, they can gain significant control over the endpoint and potentially evade detection by security operations teams.

## Recommendation

1. Enable process creation logging (e.g., Sysmon Event ID 1 or Windows Event ID 4688) across all endpoints.
2. Normalize endpoint process telemetry into the CIM (Common Information Model) or equivalent schema to ensure accurate path analysis.
3. Deploy the provided Sigma rule to identify processes that match the names of legitimate Windows system binaries but execute outside of protected system directories (e.g., C:\Windows\System32\).
4. Tune the analytic by creating allowlists for third-party software that legitimately installs binaries into non-standard locations.
