---
title: Detecting PowerShell-Based Ingress Tool Transfers
slug: 2026-08-powershell-remote-download
description: Detection of attackers using PowerShell to download executable, script, or library files from untrusted remote domains as part of command and control activity.
date: "2026-08-31T23:52:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - powershell
  - command-and-control
  - ingestion
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Attackers frequently leverage PowerShell to perform ingress tool transfers as part of their command and control strategy.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can also abuse signed utilities to drop these files.
    confidence_band: high
rules:
  - title: Detect Remote File Download via PowerShell
    description: Identifies PowerShell being used to download an executable file, DLL, or script from an untrusted remote destination.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1059.001
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy PowerShell download detection rule
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 33f306e8-417c-411b-965c-c2812d6d3f4d
  hunt_leads:
    - lead: Search for PowerShell processes with high volume of external network connections
      technique_id: T1105
      data_needed:
        - DNS and socket connection logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: PowerShell is frequently used for ingress tool transfer.
  mitigation_plan:
    - priority: medium
      action: Implement strict PowerShell execution policy and constrained language mode
      owner: IT Operations
      addresses: T1059.001
      evidence: General mitigation for PowerShell misuse
---

Attackers frequently leverage PowerShell to perform ingress tool transfers, moving malware or post-exploitation tooling from external systems into a compromised environment. By utilizing native system administration utilities, actors attempt to blend in with legitimate automation and maintenance tasks. This threat activity involves PowerShell processes making network connections for DNS resolution to identify remote resources, followed by the creation of potentially malicious files on the local filesystem.

Defenders should prioritize monitoring for PowerShell execution that culminates in file creation events, specifically when the domain resolution does not align with known trusted services (e.g., Microsoft update endpoints, standard package managers, or internal infrastructure). Given the prevalence of PowerShell in administrative routines, effective detection requires correlation between network events (DNS lookups) and file system events, combined with contextual filtering to suppress benign administrative activity.

## Attack Chain

1. Attacker establishes initial access or presence on a target Windows host.
2. Attacker launches PowerShell or PowerShell ISE to facilitate file retrieval.
3. PowerShell performs a DNS query to resolve a remote, untrusted, or attacker-controlled domain.
4. The network connection is successfully established to the resolved IP address.
5. The PowerShell process invokes download commands (e.g., Invoke-WebRequest, IEX) to fetch the payload.
6. PowerShell writes the retrieved content to the disk (e.g., an .exe, .dll, or .ps1 file).
7. The file creation event is logged by the system, identifying the PowerShell process as the actor.
8. Attacker subsequently executes the downloaded file to advance their objective, such as persistence or lateral movement.

## Impact

Successful ingress tool transfer allows attackers to introduce secondary malware, backdoors, or credential harvesting tools into a network. This facilitates long-term persistence, lateral movement, and data exfiltration. If left undetected, this activity provides the attacker with a platform to expand their footprint across the organization's infrastructure.

## Recommendation

1. Deploy the provided Sigma detection rule to monitor for PowerShell-initiated downloads.
2. Baseline your environment's PowerShell usage to identify legitimate update or automation domains that should be added to the exclusion list.
3. Enable Sysmon or Elastic Defend to capture both network (DNS) and file creation events, ensuring process-level lineage is available for investigation.
4. Use the provided investigation guide to analyze the parent process tree, examine digital signatures, and assess the reputation of external domains identified in the DNS logs.
