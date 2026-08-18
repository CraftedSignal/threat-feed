---
title: Akira Ransomware Affiliate Abuses Safe Mode to Evade EDR
slug: 2026-08-akira-safe-mode
description: An Akira ransomware affiliate gained initial access via a SonicWall VPN and attempted to evade security controls by rebooting the host into Safe Mode, an anti-EDR tactic that ultimately caused the ransomware to crash.
date: "2026-08-18T20:50:45Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Akira
tags:
  - ransomware
  - akira
  - edr-evasion
  - sonicwall
vendors:
  - SonicWall
  - Microsoft
products:
  - SonicWall SSL VPN
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: After gaining access via an exposed SonicWall VPN, an Akira affiliate rebooted the victim host into Safe Mode with Networking to defeat EDR.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Safe Mode is a boot mode that only loads essential drivers and services, disabling most third-party software.
    confidence_band: high
references:
  - https://www.huntress.com/blog/akira-hits-safe-mode-ransomware-rebooting-around-edr
iocs:
  - type: ip
    value: 72.23.77.35
  - type: hash_sha256
    value: e2356c742c74cce5c6b6100162d0071a3f71e2fed2ed895c2011061a95b3299a
  - type: hash_sha256
    value: 414b9985f46714f44dd1bd63860d2a48dcfababcfe5c712a4b4f575378127a56
ioc_counts:
  hash_sha256: 2
  ip: 1
rules:
  - title: Detect Safe Mode Boot Configuration Change
    description: Detects the modification of Windows boot configuration to trigger a reboot into Safe Mode, often used by attackers to disable security products.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block IOC 72.23.77.35 on network edge
      owner: SOC
      due: 2h
      evidence: Verified attacker source IP
  hunt_leads:
    - lead: Search for unauthorized msconfig or bcdedit executions
      technique_id: T1562.001
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly links boot config changes to EDR evasion
  mitigation_plan:
    - priority: immediate
      action: Enable MFA on all VPN and remote access gateways
      owner: IT Operations
      addresses: Initial access vector
      evidence: Source identifies lack of MFA on VPN as root cause
---

In early August 2026, a Huntress-observed Akira ransomware affiliate executed a targeted attack against a victim environment. The threat actor initially gained access through an exposed SonicWall SSL VPN appliance lacking multi-factor authentication. Following successful authentication, the attacker pivoted to the domain controller, conducted extensive Active Directory reconnaissance, and staged data for exfiltration. In a notable attempt to bypass endpoint detection and response (EDR) solutions and Microsoft Defender, the attacker modified the host boot configuration to force a reboot into Safe Mode with Networking. This maneuver successfully disabled third-party security agents; however, it also deprived the Akira ransomware payload of the necessary resources, resulting in an out-of-memory failure that prevented file encryption. Despite the failure of the ransomware detonation, the attacker successfully exfiltrated sensitive data to an external S3 bucket prior to the reboot.

## Attack Chain

1. Initial access is established by the threat actor using valid credentials via an exposed SonicWall SSL VPN appliance (T1190).
2. The attacker establishes remote persistent access using AnyDesk, identified by peer Client-ID 1778787240.
3. Reconnaissance is performed on Active Directory, with output files written to C:\ProgramData\AdUsers.txt and C:\ProgramData\AdComp.txt (T1087.002).
4. Data shares are discovered, collected, and compressed using WinRAR.exe (T1560.001).
5. Staged data is exfiltrated to an attacker-controlled S3 bucket using the s5cmd utility (T1567.002).
6. The attacker executes a command to modify boot configuration via msconfig.exe, setting the system to reboot into Safe Mode (T1562.001).
7. The system reboots into Safe Mode (EID 27: SAFEBOOT:NETWORK), which terminates EDR processes and disables Microsoft Defender real-time protection (T1547.001).
8. The Akira payload attempts to execute in the restricted environment, causing an out-of-virtual-memory crash, thereby failing to encrypt the host.

## Impact

While the Akira ransomware encryption failed due to the host's transition into Safe Mode, the attacker successfully achieved data exfiltration. The loss of sensitive information exposes the organization to double-extortion tactics, where the actor threatens to publicly leak exfiltrated data unless a ransom is paid. The incident highlights a shifting landscape where ransomware affiliates are increasingly using environmental modification to evade automated security responses.

## Recommendation

- Enable Sysmon or Windows Event Log auditing (Event ID 4697 or 7045) to detect modifications to the boot configuration via msconfig or BCDedit.
- Implement a policy to restrict VPN access to specific source IP addresses and enforce mandatory MFA for all VPN and remote access sessions.
- Deploy the provided Sigma rule to alert on unauthorized attempts to set the Windows boot mode to 'Safe Mode'.
- Monitor for the execution of file archival utilities like WinRAR.exe in non-standard directories or by non-admin accounts.
- Review network egress logs for unauthorized data movement to cloud storage providers (specifically S3) using utilities like s5cmd.exe.
