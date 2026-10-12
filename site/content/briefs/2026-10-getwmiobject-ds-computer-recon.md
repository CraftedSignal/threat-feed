---
title: Detection of Active Directory Enumeration via WMI
slug: 2026-10-getwmiobject-ds-computer-recon
description: Adversaries utilize the Get-WmiObject cmdlet via PowerShell to perform Active Directory domain computer enumeration, facilitating lateral movement planning.
date: "2026-10-12T17:46:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - reconnaissance
  - active-directory
  - powershell
  - discovery
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
    evidence: This activity is significant as it indicates potential reconnaissance efforts by adversaries to enumerate domain computers and gather situational awareness within Active Directory.
    confidence_band: high
rules:
  - title: Detect AD Reconnaissance via Get-WmiObject ds_computer
    description: Detects PowerShell execution using Get-WmiObject to query the ds_computer class in the root\directory\ldap namespace
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
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
    - action: Deploy Sigma detection for WMI ds_computer enumeration
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command line indicators
  hunt_leads:
    - lead: Search historical logs for Get-WmiObject -Class ds_computer
      technique_id: T1018
      data_needed:
        - Process creation logs with command-line arguments
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of adversary behavior
  mitigation_plan:
    - priority: medium
      action: Restrict administrative PowerShell access to authorized accounts only
      owner: IT Operations
      addresses: T1018
      evidence: Standard hardening practice for domain discovery
---

This threat involves the use of PowerShell to execute `Get-WmiObject` queries against the `root\directory\ldap` namespace, specifically targeting the `ds_computer` class. This technique is commonly employed by threat actors during the reconnaissance phase of an attack to enumerate Active Directory (AD) computers. By querying the LDAP namespace, an attacker can map the network, identify domain-joined workstations and servers, and subsequently target high-value assets for lateral movement or data exfiltration. Because this activity is highly specific to internal domain discovery, it is considered a strong indicator of malicious intent when observed in environments lacking corresponding authorized administrative work orders.

## Attack Chain

1. Initial access is established on a domain-joined endpoint via phishing or exploit.
2. The attacker executes a PowerShell process (`powershell.exe` or `cmd.exe` spawning PowerShell).
3. The attacker initiates a WMI query using `Get-WmiObject`.
4. The query specifically targets the `root\directory\ldap` namespace to interact with Active Directory.
5. The `ds_computer` class is specified to retrieve the list of computer objects in the domain.
6. The query results are parsed or exfiltrated to the attacker's C2 to map the network environment.
7. The adversary uses the gathered intelligence to identify target systems for further exploitation or lateral movement.

## Impact

Successful execution of this enumeration technique allows an adversary to perform situational awareness within an Active Directory environment. This provides the attacker with a target list of systems, potentially exposing critical servers and workstations. This mapping is a precursor to lateral movement, privilege escalation, and systemic compromise, increasing the risk of data theft or ransomware deployment.

## Recommendation

1. Deploy the Sigma rules below to monitor for PowerShell command lines invoking WMI queries against the `ds_computer` class.
2. Enable process-creation logging (e.g., Sysmon Event ID 1 or Windows Event ID 4688) with full command-line arguments to ensure visibility into PowerShell execution.
3. Baseline the usage of `Get-WmiObject` in your environment to identify authorized administrative troubleshooting patterns and tune out false positives.
4. Alert on instances where this command is executed by non-administrative user accounts.
