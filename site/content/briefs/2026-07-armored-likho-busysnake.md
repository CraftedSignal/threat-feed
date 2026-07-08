---
title: Armored Likho APT Leverages BusySnake Stealer with AI-Generated Loaders and Phishing
slug: 2026-07-armored-likho-busysnake
description: The Armored Likho APT group is conducting a spear-phishing campaign against government and energy sectors in Russia, Kazakhstan, and Brazil, using AI-generated loaders and the Python-based BusySnake Stealer to exfiltrate credentials and sensitive data.
date: "2026-07-08T14:38:38Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Armored Likho
tags:
  - apt
  - infostealer
  - phishing
  - python
  - windows
  - government
  - energy
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The attack chain starts with spear-phishing messages, with lure themes ranging from official government notices to humanitarian aid applications and psychological tests. These emails contain malicious archive attachments
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Once a victim extracts and opens the attachment, both delivery paths lead to BusySnake Stealer being installed on the device.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: In the LNK route, an obfuscated PowerShell command downloads and runs the loader.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: From there, the loader pulls the required Python components and the BusySnake payload from GitHub-hosted archives before setting up persistence. ... AquilaRAT uses MicrosoftOfficeUpdate, while BusySnake Stealer uses WindowsHelper.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: From there, the loader pulls the required Python components and the BusySnake payload from GitHub-hosted archives
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: The malware actively logs clipboard contents, harvests browser cookies, pulls session tokens from Telegram, documents exfiltration, screenshot capture, scrapes two-factor authentication secrets, and searches for cryptocurrency wallets.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1115
    technique_name: Clipboard Data
    evidence: The malware actively logs clipboard contents
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: documents exfiltration, scrapes two-factor authentication secrets, and searches for cryptocurrency wallets.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: The attackers also built reverse SSH tunneling into BusySnake, giving them a way to maintain remote access, manually inspect compromised systems, and pull out targeted files after infection.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: The attackers also built reverse SSH tunneling into BusySnake, giving them a way to maintain remote access
    confidence_band: high
references:
  - https://hackread.com/armored-likho-government-energy-busysnake-stealer/
rules:
  - title: BusySnake Stealer - LNK Executing Obfuscated PowerShell
    description: Detects the execution of obfuscated PowerShell commands by explorer.exe or cmd.exe, a common delivery method for BusySnake Stealer via malicious LNK files.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: BusySnake Stealer - Scheduled Task Persistence (WindowsHelper)
    description: Detects the creation of the 'WindowsHelper' scheduled task, used by BusySnake Stealer for persistence on compromised systems.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The newly identified Armored Likho APT group is actively targeting government agencies and electric power organizations across Russia, Kazakhstan, and Brazil through an extensive spear-phishing operation. Observed by Kaspersky researchers, this group deploys a sophisticated malware toolkit, including the Python-based BusySnake Stealer, augmented by AI-generated loaders designed to obscure their operational footprint and complicate attribution. The primary objective of these attacks is cyber-espionage, focusing on credential harvesting and maintaining long-term access to critical infrastructure environments. The campaign, which shows no signs of slowing down, began with spear-phishing messages distributing malicious attachments that ultimately lead to the installation of the BusySnake payload, facilitating comprehensive data exfiltration and remote access.

## Attack Chain

1. Armored Likho initiates attacks via spear-phishing messages with lure themes such as official government notices, humanitarian aid applications, or psychological tests.
2. Emails contain malicious archive attachments, delivered either as Nullsoft Scriptable Install System (NSIS)-built EXE droppers or malicious LNK shortcuts.
3. If the victim opens an NSIS EXE dropper, it launches a legitimate process and injects a malicious loader code.
4. Alternatively, if the victim opens a malicious LNK shortcut, it executes an obfuscated PowerShell command.
5. The PowerShell command or injected loader downloads required Python components and the BusySnake payload from GitHub-hosted archives.
6. The loader establishes persistence on the compromised device, often creating a scheduled task named `WindowsHelper`.
7. BusySnake Stealer then actively logs clipboard contents, harvests browser cookies, pulls session tokens from Telegram, captures screenshots, scrapes two-factor authentication secrets, and searches for cryptocurrency wallets, exfiltrating this sensitive data.
8. Attackers establish reverse SSH tunneling to maintain remote access, manually inspect systems, and pull additional targeted files after initial infection.

## Impact

The Armored Likho group's activities have a severe impact on targeted government and energy organizations in Russia, Kazakhstan, and Brazil. Successful compromises lead to the exfiltration of credentials, sensitive documents, and other high-value data, enabling long-term espionage and unauthorized access to critical infrastructure. The BusySnake Stealer comprehensively collects clipboard data, browser cookies, Telegram session tokens, screenshots, two-factor authentication secrets, and cryptocurrency wallet information. The establishment of reverse SSH tunnels grants attackers persistent remote access, allowing for ongoing surveillance, data collection, and manual exfiltration, potentially disrupting operations or compromising national security.

## Recommendation

* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious LNK execution and scheduled task creation.
* Implement email security solutions capable of detecting and blocking spear-phishing attempts, particularly those with malicious archive attachments.
* Monitor `powershell.exe` process creation and network connections for unusual activity, especially outbound connections to file hosting services like GitHub.
* Enable Sysmon process-creation logging to capture `schtasks.exe` command lines and PowerShell activity for deeper forensic analysis.
* Regularly educate users on identifying spear-phishing emails and reporting suspicious messages, emphasizing the dangers of opening unexpected attachments.
