---
title: Windows Network Share Discovery via Net Command
slug: 2026-10-windows-net-share-discovery
description: Attackers utilize the Windows 'net' utility to discover and enumerate network shares as a precursor to lateral movement, privilege escalation, or data exfiltration.
date: "2026-10-12T18:16:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - network-reconnaissance
  - discovery
  - collection
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1135
    technique_name: Network Share Discovery
    evidence: The following analytic identifies network share discovery and collection activities performed on Windows systems using the Net command.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1039
    technique_name: Data from Network Shared Drive
    evidence: Attackers often use network share discovery to identify accessible shared resources within a network, which can be a precursor to privilege escalation or data exfiltration.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1135/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1135/T1135.yaml
rules:
  - title: Detect Windows Network Share Enumeration via Net
    description: Detects the use of the 'net' command to view or interact with network shares, a technique often used for discovery.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1135
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
    - action: Deploy Sigma rule and tune for existing admin activity
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for process monitoring
  hunt_leads:
    - lead: Search for instances of net.exe initiated by non-administrative user accounts or uncommon parent processes
      technique_id: T1135
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Analytic note on filtering administrators
---

The 'net' command in Windows is a legitimate administrative tool that is frequently abused by threat actors to perform reconnaissance and identify accessible shared resources across a corporate network. By executing 'net view' or 'net use', an attacker can map available network shares on local and remote systems without triggering complex security alerts. This activity is a classic indicator of post-exploitation discovery, often occurring after initial access and prior to data collection or lateral movement. Monitoring process execution patterns for 'net.exe' with specific command-line arguments allows detection engineers to identify unauthorized enumeration attempts. Defenders should focus on normalizing endpoint process telemetry to identify unusual users or unexpected parent processes triggering these commands, while filtering out known administrative service accounts and legitimate automated maintenance scripts.

## Attack Chain

1. Attacker gains initial access to a compromised endpoint using a secondary payload or exploit.
2. Attacker establishes a command shell (e.g., cmd.exe or PowerShell) on the endpoint.
3. Attacker executes 'net view \\&lt;computername>' to identify available shares on a target system.
4. Attacker executes 'net use' to list current connections or map a network share to a local drive letter.
5. Attacker navigates the mapped shares to locate sensitive files or documents (T1039).
6. Attacker exfiltrates identified data or moves laterally to the target system.

## Impact

Successful exploitation leads to the mapping of internal network architecture and unauthorized access to sensitive file shares. This reconnaissance phase is critical for attackers to identify high-value targets for ransomware deployment, intellectual property theft, or escalation of privileges, potentially resulting in large-scale data breaches.

## Recommendation

* Deploy the Sigma rule provided in this brief to detect the execution of 'net.exe' with enumeration arguments.
* Enable command-line logging via Sysmon (Event ID 1) or Windows Security Event ID 4688 to capture the full execution context of administrative tools.
* Baseline legitimate administrative usage of 'net' in the environment to create an allowlist filter and reduce false-positive rates.
* Integrate endpoint process logs with a SIEM and map them to the Common Information Model (CIM) to ensure consistent detection logic.
