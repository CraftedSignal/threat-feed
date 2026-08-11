---
title: DeadLock Ransomware Leverages Polygon Smart Contracts for Resilient C2
slug: 2026-08-deadlock-ransomware
description: The DeadLock ransomware group employs decentralized infrastructure, including Polygon smart contracts, to rotate proxy servers and host data leak blogs, complicating traditional takedown efforts.
date: "2026-08-11T18:45:27Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - DeadLock
tags:
  - ransomware
  - blockchain
  - extortion
  - data-exfiltration
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify Tools'
    evidence: For defense evasion and minimizing forensic evidence, it systematically erases logs and disables logging via Registry manipulation to prevent recording future events.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: Attacks mounted by the group are known to encrypt files with the .dlock extension.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
    evidence: The HTML file sends and receives messages from a server that acts as a proxy, the details of which are retrieved and managed using a blockchain-based approach.
    confidence_band: high
references:
  - https://thehackernews.com/2026/08/deadlock-ransomware-uses-polygon-smart.html
iocs:
  - type: ip
    value: 138.226.236.51
ioc_counts:
  ip: 1
rules:
  - title: Detect DeadLock Ransomware HTML Recovery Chat Drop
    description: Detects the creation of DeadLock ransomware's self-contained HTML recovery chat files in system directories.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1486
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
    - action: Block the IP 138.226.236.51 at the perimeter firewall.
      owner: SOC
      due: 2h
      evidence: IP identified as a proxy server for DeadLock C2.
  hunt_leads:
    - lead: Search for .dlock file extensions or files matching 'RECOVERY_CHAT.*.html' on endpoints.
      technique_id: T1486
      data_needed:
        - Endpoint file scan telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Artifacts are drop indicators of DeadLock activity.
  mitigation_plan:
    - priority: immediate
      action: Restrict the use of AnyDesk to authorized administrators via EDR/AppLocker.
      owner: IT Operations
      addresses: T1219
      evidence: AnyDesk is explicitly used by the actor for remote control.
---

DeadLock ransomware, active since July 2025, has evolved its operational infrastructure to utilize decentralized technologies. The group uses a custom recovery ecosystem that integrates the Session messaging network with blockchain-backed services to manage communications and data exfiltration. By leveraging Polygon smart contracts, DeadLock operators can dynamically update proxy server addresses for their interactive HTML-based recovery chat and maintain a decentralized data leak blog via the Wasabi protocol. This architecture eliminates reliance on traditional, disruptible web infrastructure. The ransomware uses a hybrid cryptographic design (Curve25519 and XChaCha20) and features geofencing, resource-aware throttling (capping CPU/memory usage), and extensive defense evasion techniques. With 96 victims identified primarily in Italy, Spain, Poland, Türkiye, and the U.S., the group continues to expand its reach by partnering with affiliates of other ransomware operations like Lynx and INC.

## Attack Chain

1. Initial access is established, often involving the use of AnyDesk for remote control of compromised hosts.
2. The ransomware payload is deployed, which performs environment reconnaissance and applies geofencing to avoid specific CIS and Middle Eastern regions.
3. A PowerShell script is executed to identify and stop non-allowlisted services and prevent their automatic restart.
4. The malware clears event logs and modifies the Registry to disable further logging, effectively minimizing forensic footprint.
5. Volume Shadow Copies are deleted to prevent easy file recovery, followed by the encryption of files using the .dlock extension.
6. The ransomware performs resource-aware throttling to maintain system responsiveness, pausing encryption if CPU load exceeds 70% or memory exceeds 29%.
7. A custom ".ico" file is written to disk to modify file icons, and the desktop wallpaper is updated with a ransom notification.
8. The malware drops a self-contained HTML file (RECOVERY_CHAT.&lt;UID>.html) to drive roots and Desktop folders, which facilitates communication and data leak access via Polygon-hosted proxy addresses.

## Impact

DeadLock ransomware has successfully targeted 96 organizations as of August 2026. Victims suffer from double extortion, where sensitive data is exfiltrated and threatened for release on a decentralized blog. The use of blockchain-based infrastructure increases the persistence of the threat actor's communications, making it significantly harder for law enforcement and security teams to disrupt the negotiation and extortion phases.

## Recommendation

- Deploy the Sigma rules provided in this brief to detect the drop and execution of the ransom recovery HTML files.
- Implement monitoring for PowerShell scripts that interact with shadow copy deletion commands, such as 'vssadmin delete shadows'.
- Monitor for unauthorized use of remote access tools like AnyDesk within the environment.
- Configure SIEM rules to alert on abnormal Registry modifications intended to disable Windows Event Logging.
- Block egress traffic to the identified proxy server IP (138.226.236.51) at the firewall or DNS resolver level.
