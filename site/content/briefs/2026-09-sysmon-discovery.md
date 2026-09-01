---
title: Sysmon Discovery via Driver Altitude Search
slug: 2026-09-sysmon-discovery
description: Adversaries use findstr.exe to identify the presence of Sysmon by searching for its default driver altitude, 385201, regardless of whether the service name has been altered.
date: "2026-09-01T12:28:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - discovery
  - defense-evasion
  - reconnaissance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1518
    technique_name: Software Discovery
    evidence: Detects usage of findstr with the argument 385201, which could indicate potential discovery of an installed Sysinternals Sysmon service.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_findstr_sysmon_discovery_via_default_altitude.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518.001/T1518.001.md#atomic-test-5---security-software-discovery---sysmon-service
rules:
  - title: Detect Sysmon Discovery via Driver Altitude using Findstr
    description: Detects usage of findstr or find with the argument 385201, which indicates discovery of the Sysmon driver altitude.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1518.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the provided Sigma rule for monitoring Sysmon discovery
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in brief
  hunt_leads:
    - lead: Search for historical execution of findstr or find with '385201' argument
      technique_id: T1518.001
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly identifies this as a discovery pattern
---

Security software discovery is a critical reconnaissance step for threat actors seeking to evade detection or disable security controls. A known technique for identifying Sysmon installations involves querying the system for the presence of the default Sysmon driver altitude, 385201. Attackers use common Windows binaries like findstr.exe or find.exe to search for this specific altitude value within the output of system commands or registry queries. Because the driver altitude is tied to the kernel-mode driver registration and not the user-mode service name, this method remains effective even when defenders attempt to obfuscate Sysmon by renaming the service executable. Monitoring for these specific command-line arguments allows security operations teams to detect reconnaissance activity before an attacker attempts to disable or bypass monitoring capabilities.

## Attack Chain

1. Attacker establishes initial access on a Windows endpoint.
2. Attacker executes system discovery commands to identify installed security tools.
3. Attacker uses a command like "fltmc filters" or "reg query" to list installed drivers or registry keys.
4. Attacker pipes the output of these commands into "findstr.exe 385201" or "find.exe 385201".
5. The utility identifies the specific registry entry or filter list containing the Sysmon driver altitude.
6. The process concludes by confirming the presence and path of the Sysmon driver.
7. Attacker proceeds to disable the identified security service or clear the configuration.

## Impact

Successful reconnaissance allows attackers to map the defense-in-depth posture of an organization, specifically targeting security instrumentation for neutralization. Once identified, Sysmon instances can be uninstalled, stopped, or have their configuration modified to evade detection of further malicious actions, potentially leading to long-term persistence and unauthorized exfiltration of sensitive data.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious usage of findstr.exe or find.exe targeting the Sysmon driver altitude. Enable Sysmon or Windows Event Log (Event ID 4688) process-creation logging to ensure command-line arguments are captured and forwarded to the SIEM.
