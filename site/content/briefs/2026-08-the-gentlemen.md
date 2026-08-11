---
title: The Gentlemen Ransomware Group Activity
slug: 2026-08-the-gentlemen
description: The Gentlemen ransomware group leverages VPN/firewall exploits to gain initial access, utilizes BYOVD techniques to disable security tools, and propagates ransomware via the NETLOGON share.
date: "2026-08-11T17:48:26Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - The Gentlemen
vendors:
  - Fortinet
  - Veeam
  - SAP
  - Oracle
  - Microsoft
  - AnyDesk
products:
  - FortiGate
  - Veeam Backup & Replication
  - SAP
  - Oracle Database
  - MySQL
  - AnyDesk
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: The group relies on placing an account into a privileged group to guarantee they cannot be locked out.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
    evidence: Because every computer in the domain automatically connects to NETLOGON, dropping the ransomware payload there lets it spread to the entire environment at once.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify Tools'
    evidence: The attackers then pair the driver with a separate tool called All.exe to exploit it and force-terminate antivirus and endpoint protection processes.
    confidence_band: high
rules:
  - title: Detect Addition of Users to Privileged Windows Security Groups
    description: Detects the use of 'net' commands to add users to high-privilege domain or local groups, a common technique for persistence and lateral movement.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1098
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

The Gentlemen is a ransomware group active since August 2025, primarily targeting critical sectors such as financial services, healthcare, and manufacturing. The group is known for its sophisticated TTPs, including extensive network mapping and deliberate efforts to weaken security tooling before initiating encryption. Their operation relies on a mix of legitimate administrative utilities and custom-loaded drivers to maintain stealth. The group has claimed responsibility for over 600 breaches across 80 countries. Defenders should monitor for post-compromise behaviors, specifically the elevation of accounts into privileged security groups and the abuse of standard Windows domain infrastructure for lateral tool transfer.

## Attack Chain

1. Initial access is achieved through exploitation of internet-exposed appliances, such as FortiGate VPN/firewall interfaces, or via compromised credentials.
2. Internal reconnaissance is performed using the commodity tool Advanced IP Scanner to map network segments and identify administrative accounts.
3. Privilege escalation is achieved by executing the PowerRun.exe utility to gain elevated administrative rights.
4. Defense evasion is conducted using a Bring Your Own Vulnerable Driver (BYOVD) technique by loading the signed driver ThrottleBlood.sys.
5. The attacker forces termination of antivirus and security processes by exploiting the loaded driver with a custom tool identified as All.exe.
6. Persistence and lateral movement are maintained using AnyDesk and by creating/elevating accounts into privileged Windows security groups (e.g., Domain Admins).
7. Data exfiltration is performed using WinSCP to move sensitive information over encrypted channels.
8. Final impact is achieved by distributing the ransomware payload via the domain-wide NETLOGON share, causing mass encryption across all joined machines.

## Impact

The Gentlemen's operations result in severe operational disruption through mass encryption of enterprise environments and the exfiltration of sensitive organizational data. Reported targets include critical services such as hospitals and healthcare networks, as well as financial and manufacturing entities. Impacted systems often require significant recovery efforts, as the group systematically disables backup and database services like Veeam, SAP, Oracle, and MySQL prior to encryption.

## Recommendation

1. Deploy Sigma rules to monitor the 'net' utility for additions of accounts to high-privilege groups (Administrators, Domain Admins, etc.) as detailed in the rule below.
2. Baseline and audit changes to privileged group memberships; cross-reference these changes against established change management tickets.
3. Monitor for unauthorized use of legitimate RMM tools like AnyDesk within the environment.
4. Implement strict egress filtering to limit unauthorized WinSCP connections to unknown external infrastructure.
5. Harden the NETLOGON and SYSVOL shares by restricting write access to only verified, necessary administrative service accounts.
