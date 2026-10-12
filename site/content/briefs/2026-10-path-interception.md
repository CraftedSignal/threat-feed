---
title: Detection of Privilege Escalation via Unquoted Service Paths
slug: 2026-10-path-interception
description: Attackers exploit unquoted service paths on Windows systems to achieve privilege escalation by placing malicious executables in directories that the Windows Service Controller inadvertently executes with system-level privileges.
date: "2026-10-12T17:39:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - persistence
  - windows
  - edr
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: The following analytic identifies the creation of a program executable in an unquoted service path, a common technique for privilege escalation.
    confidence_band: high
rules:
  - title: Detect Path Interception by Creation of Program Executable
    description: Detects the creation of an executable in an unquoted service path by monitoring child processes spawned by services.exe.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1574.009
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - System Administration
  immediate_actions:
    - action: Deploy detection logic to identify unquoted service paths and monitor process creation.
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic logic.
  mitigation_plan:
    - priority: immediate
      action: Identify and quote all unquoted service paths in the system environment.
      owner: System Administration
      addresses: T1574.009
      evidence: Industry best practices for service configuration.
---

This threat involves the exploitation of Windows services that utilize unquoted paths containing spaces. When a service path is not enclosed in quotes, the Windows Service Controller attempts to interpret the path by looking for executable files in each subdirectory of the path string. Attackers can leverage this behavior by planting a malicious executable, such as a .exe, .bat, or .com file, in a directory that occurs early in the search path. If the service is running with high privileges, the maliciously placed file will be executed with those same privileges upon service startup. This technique is a well-documented method for achieving privilege escalation and maintaining persistence on compromised Windows endpoints. Detection relies on monitoring process creation events where the parent process is the service control manager (services.exe) and the child process name does not match the expected service executable, signaling potential path interception.

## Attack Chain

1. Attacker identifies a Windows service configured with an unquoted executable path containing spaces (e.g., C:\Program Files\App Folder\service.exe).
2. Attacker checks for write permissions on higher-level directories within that path (e.g., C:\Program Files\).
3. Attacker places a malicious executable named 'Program.exe' in the C:\Program Files\ directory.
4. The Windows Service Controller triggers the service, interpreting 'C:\Program' as the executable path due to the missing quotes.
5. The system executes the attacker-controlled 'Program.exe' located at C:\Program.exe.
6. The malicious executable runs under the security context of the service (often LocalSystem or an administrative account).
7. Attacker gains elevated code execution privileges on the target endpoint.
8. Attacker uses the elevated context to further compromise the system or establish persistent access.

## Impact

Successful exploitation allows attackers to gain elevated privileges, typically running code as SYSTEM or as a high-privileged service user. This enables full system compromise, the ability to bypass security controls, and the establishment of persistent control over the affected Windows endpoint.

## Recommendation

* Deploy the provided Sigma rule to monitor for suspicious child processes spawned by services.exe where the process path appears to be an interception of a legitimate service path.
* Audit existing Windows services for unquoted paths using PowerShell or administrative tools and add double quotes to any service paths found to be vulnerable.
* Restrict write permissions on directories that appear in service search paths to prevent unauthorized placement of malicious binaries.
* Use EDR telemetry (such as Sysmon Event ID 1) to alert on instances where service-related process creation involves files residing in suspicious or unexpected path locations.
