---
title: Silver Fox Campaign Distributes Malware via Spoofed Software Websites
slug: 2026-09-silver-fox-fake-installers
description: The threat cluster Silver Fox is targeting users with high-fidelity clone websites to distribute malicious installers that disable security features and deploy backdoors like ValleyRAT and Gh0st RAT.
date: "2026-09-02T18:24:08Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Silver Fox
tags:
  - silver-fox
  - malware
  - defense-evasion
  - windows
  - phishing
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The campaign has used bogus software-download websites to impersonate trusted vendors and distribute malicious installers.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: The malware is also responsible for... configuring Microsoft Defender exclusions via PowerShell.
    confidence_band: high
iocs:
  - type: domain
    value: app-microsoft-edge.com.cn
  - type: domain
    value: baidu-pan.com.cn
  - type: domain
    value: calibre-ebook.com.cn
  - type: domain
    value: cn-drawio.com.cn
  - type: domain
    value: gw-sogou.com.cn
  - type: domain
    value: kaspersky-lab.hl.cn
  - type: domain
    value: mindmoster.com.cn
  - type: domain
    value: ocam-pc.com.cn
  - type: domain
    value: pc-razerzone.com.cn
  - type: domain
    value: sejda.hl.cn
  - type: domain
    value: steelseries-cn.com.cn
  - type: domain
    value: translate-youdao.hl.cn
  - type: domain
    value: zh-diskgenius.com.cn
  - type: domain
    value: iualef.net
  - type: domain
    value: oijfwe.net
ioc_counts:
  domain: 15
rules:
  - title: Detect Modification of Windows Update Services
    description: Detects attempts to stop or disable Windows Update services, often used by malware for persistence and to prevent security patching.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1489
    data_sources:
      - process_creation
      - windows
  - title: Detect Microsoft Defender Exclusion Modification
    description: Detects PowerShell commands used to modify Microsoft Defender exclusions, a common persistence and evasion tactic.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - CTI
    - Detection Engineering
  immediate_actions:
    - action: Block listed C2 domains and download source at DNS resolver
      owner: SOC
      due: 1h
  hunt_leads:
    - lead: Search for scheduled tasks created as SYSTEM that execute icacls or PowerShell commands related to Defender exclusions.
      technique_id: T1562.001
      priority: high
      confidence: high
      disposition: hunt_now
  mitigation_plan:
    - priority: immediate
      action: Review and audit existing Microsoft Defender exclusions for unauthorized entries.
      owner: IT Operations
---

The threat cluster identified as Silver Fox (also known as Yinhu) is conducting an active, multi-industry malware campaign targeting organizations primarily in China, including logistics, manufacturing, government, and healthcare sectors. The campaign leverages sophisticated, high-fidelity clones of legitimate vendor software download pages hosted on .com.cn and .hl.cn infrastructure. Users are tricked into downloading ZIP archives from external infrastructure, which contain wrapper installers. Upon execution, the malware performs aggressive defense evasion, including disabling Windows Update services (wuauserv, UsoSvc, uhssvc, WaaSMedicSvc), clearing the SoftwareDistribution cache, and modifying Microsoft Defender exclusions via PowerShell. The campaign has been observed deploying established backdoors such as ValleyRAT (WinOS 4.0) and Gh0st RAT, often utilizing DLL sideloading techniques through legitimate signed applications to maintain persistent, stealthy access.

## Attack Chain

1. User navigates to a spoofed vendor download site hosted on attacker-controlled domains (e.g., app-microsoft-edge.com.cn).
2. Victim downloads a ZIP archive containing a wrapper executable (e.g., a_instapp83353001.exe) or triggers an MSI-based installer chain.
3. The installer executes, launching a primary payload that establishes persistence through system-level scheduled tasks.
4. The malware runs as SYSTEM, modifying folder DACLs using icacls to prevent unauthorized deletion by users.
5. The malware disables critical Windows Update services and deletes the SoftwareDistribution cache to prevent security patching.
6. The process modifies Microsoft Defender exclusions via PowerShell to whitelist its own directory.
7. The malware executes secondary payloads or sideloads malicious DLLs through legitimate software (e.g., QN Wallpaper) to bypass security controls.
8. Backdoors (ValleyRAT/Gh0st RAT) establish command-and-control communication over non-standard ports to domains like iualef.net and oijfwe.net.

## Impact

The campaign has resulted in confirmed compromises across multiple sectors, including healthcare, government, and manufacturing. If successful, the attack grants the actor full remote control, including the ability to perform keylogging, clipboard exfiltration, screenshot capture, and arbitrary command execution. The systematic weakening of OS-level security protections creates a persistent, long-term foothold within compromised enterprise environments.

## Recommendation

1. Deploy Sigma rules to detect the modification of Windows Update services and Microsoft Defender exclusions.
2. Block the documented C2 domains (iualef.net, oijfwe.net) at the network edge and monitor for outbound traffic on non-standard ports (5090, 7031, 7032, 7088-7090, 8050, 28290, 28300).
3. Implement endpoint policy to restrict the execution of unsigned executables from non-standard temporary directories.
4. Hunt for scheduled tasks created as SYSTEM that interact with icacls or PowerShell scripts modifying Defender exclusions.
