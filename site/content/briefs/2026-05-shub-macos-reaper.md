---
title: SHub macOS Infostealer Variant 'Reaper' Spoofing Apple Security Updates
slug: 2026-05-shub-macos-reaper
description: A new variant of the 'SHub' macOS infostealer, dubbed Reaper, uses AppleScript to display a fake security update message and install a backdoor, ultimately stealing browser data, financial documents, and cryptocurrency wallet information while bypassing Terminal-based mitigations in macOS.
date: "2026-05-18T21:42:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - macos
  - infostealer
  - shub reaper
  - malware
vendors:
  - Apple
  - Google
  - Mozilla
  - Brave
  - Microsoft
  - Opera
  - Vivaldi
  - Arc
  - Orion
  - MetaMask
  - Phantom
  - 1Password
  - Bitwarden
  - LastPass
  - Exodus
  - Atomic Wallet
  - Ledger
  - Trezor
products:
  - Chrome
  - Firefox
  - Edge
  - Opera
  - Vivaldi
  - Arc
  - Orion
  - WeChat
  - Miro
  - MetaMask
  - Phantom
  - 1Password
  - Bitwarden
  - LastPass
  - Exodus
  - Atomic Wallet
  - Ledger Live
  - Trezor Suite
  - iCloud
  - Telegram
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.bleepingcomputer.com/news/security/shub-macos-infostealer-variant-spoofs-apple-security-updates/
iocs:
  - type: domain
    value: qq-0732gwh22[.]com
  - type: domain
    value: mlcrosoft[.]co[.]com
  - type: domain
    value: mlroweb[.]com
ioc_counts:
  domain: 3
rules:
  - title: Detect SHub Reaper - Suspicious AppleScript Execution via Open Command
    description: Detects execution of AppleScript via 'open' command, which may indicate malicious activity like SHub Reaper.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - macos
  - title: Detect SHub Reaper - Suspicious Curl Usage
    description: Detects curl command being used to download files and pipe to shell for execution, which is typical of malware such as SHub Reaper.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - macos
  - title: Detect SHub Reaper - Persistence via Google Update Impersonation
    description: Detects persistence via LaunchAgent masquerading as Google Update.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - file_event
      - macos
rules_count: 3
---

A new variant of the SHub macOS infostealer, dubbed Reaper, has emerged, employing a novel approach to bypass existing security mitigations. Unlike previous SHub campaigns that relied on tricking users into pasting commands in Terminal, Reaper leverages the `applescript://` URL scheme to launch the macOS Script Editor preloaded with a malicious AppleScript. This technique circumvents Apple's late March mitigations in macOS Tahoe 26.4, which aimed to block the execution of harmful commands pasted into the Terminal. SentinelOne researchers discovered that victims are lured by fake installers for WeChat and Miro applications hosted on domains designed to appear legitimate. The malware fingerprints the victim's device to detect virtual machines and VPNs, and enumerates installed browser extensions for password managers and cryptocurrency wallets, sending telemetry data to the attacker via a Telegram bot.

## Attack Chain

1.  The victim visits a malicious website impersonating WeChat or Miro.
2.  The website fingerprints the visitor's device, checking for VMs/VPNs and enumerating browser extensions. This information is sent to a Telegram bot.
3.  The website prompts the user to download a fake installer, which then uses the `applescript://` URL scheme.
4.  Clicking the URL opens the macOS Script Editor with a preloaded malicious AppleScript.
5.  If the user clicks "Run" in the Script Editor, the script displays a fake Apple security update message referencing XProtectRemediator.
6.  The script downloads a shell script using `curl` and executes it silently via `zsh`.
7.  The shell script checks for a Russian keyboard layout; if detected, the malware exits.
8.  If the keyboard layout is not Russian, the script retrieves and executes a malicious AppleScript with data theft routines via `osascript`. This script prompts the user for their macOS password, and then steals browser data, cryptocurrency wallet data, and other sensitive files. The malware establishes persistence by installing a script impersonating the Google software update and registers it using LaunchAgent, running every minute as a beacon.

## Impact

Successful infection by the SHub Reaper infostealer results in the theft of sensitive data, including browser data from Chrome, Firefox, Edge, Opera, Vivaldi, Arc, and Orion, cryptocurrency wallet data (MetaMask, Phantom), password manager data (1Password, Bitwarden, LastPass), desktop cryptocurrency wallet application data (Exodus, Atomic Wallet, Ledger Live, Trezor Suite), iCloud account data, Telegram session data, and developer configuration files. The malware also targets files on the Desktop and Documents folders, collecting documents smaller than 2MB, or images up to 6MB (total limit 150MB). Cryptocurrency wallet applications are hijacked by replacing their core application file with a malicious version downloaded from the C2 server. This gives the attacker persistent access to the compromised machine and enables further malware deployment.

## Recommendation

*   Monitor for suspicious outbound network traffic after Script Editor execution, as mentioned in the overview.
*   Monitor for the creation of new LaunchAgents and related files in the namespace of trusted vendors to detect persistence mechanisms, as recommended by SentinelOne.
*   Block access to the known malicious domains: `qq-0732gwh22[.]com`, `mlcrosoft[.]co[.]com`, and `mlroweb[.]com` at the DNS resolver based on the IOCs provided.
