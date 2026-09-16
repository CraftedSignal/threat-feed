---
title: Atomic macOS (AMOS) Stealer Activity
slug: 2026-09-amos-stealer
description: Atomic macOS (AMOS) stealer uses deceptive 'toolkit' websites to trick users into executing terminal commands that deploy credential-harvesting malware and persistent Mach-O binaries.
date: "2026-09-16T13:01:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - macos
  - malware
  - stealer
  - information-stealer
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: AMOS stealer has been distributed through ClickFix campaigns as well as through malicious ads.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: We copied text from the page and pasted it into a Terminal window on our macOS system.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The plist file at /tmp/starter contains text that hints at a newly created file in the user's /Library/Application Support/.com.apple.accountsd/ directory named .service.
    confidence_band: high
references:
  - https://unit42.paloaltonetworks.com/atomic-macos-amos-stealer-activity/
iocs:
  - type: domain
    value: getmacouscloud.com
  - type: domain
    value: ferncore13.com
  - type: ip
    value: 161.35.146.120
  - type: hash_sha256
    value: a598fcdcd49247312861ff90c16cb4a5d49fede6072e30e7416dd276668fa2a9
ioc_counts:
  domain: 2
  hash_sha256: 1
  ip: 1
rules:
  - title: Detect Suspicious Zsh Execution from Terminal
    description: Detects Zsh scripts that contain Base64-encoded data, often used by AMOS stealer to hide malicious payloads
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block listed C2 domains and IPs in egress filters.
      owner: SOC
      due: 24h
      evidence: Source provides explicit C2 infrastructure IOCs.
  hunt_leads:
    - lead: Search for processes executing Zsh scripts with base64 components in user temporary directories.
      technique_id: T1059.004
      data_needed:
        - process_creation telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker uses Zsh scripts in /tmp/ to fetch payloads.
---

Atomic macOS (AMOS) is an information stealer targeting macOS users, actively evolving and distributed through malicious advertising and social engineering campaigns. Since at least April 2024, threat actors have utilized deceptive landing pages claiming to offer "macOS toolkits" or cracked software to lure victims. The infection chain relies on users manually copying and pasting malicious instructions into a Terminal window, which initiates a multi-stage process involving Zsh scripts, GZIP-compressed payloads, and the deployment of persistent Mach-O binaries. AMOS exfiltrates sensitive data including browser credentials, cryptocurrency wallet keys, and system metadata. The infrastructure, including C2 domains and IP addresses, is highly ephemeral and frequently changes, indicating active development and a strategy to evade static detection. Defenders must prioritize monitoring for anomalous Terminal activity and unauthorized modifications to macOS library directories.

## Attack Chain

1. The victim visits a malicious website (e.g., getmacouscloud.com) advertising a fake "macOS toolkit" or software utility.
2. The site displays instructions tricking the user into copying and pasting a malicious command into the macOS Terminal.
3. The Terminal process executes the pasted command, which fetches a Zsh script from an attacker-controlled URL (e.g., ferncore13.com).
4. The downloaded Zsh script extracts and executes a Base64-encoded GZIP payload containing a secondary script and an AMOS installer binary.
5. The installer binary (/tmp/helper) is executed, often prompting the user for administrative credentials to escalate or proceed.
6. The malware establishes persistence by creating hidden files and shell scripts within the user's ~/Library/Application Support/ directory (e.g., .com.apple.accountsd/ or .com.apple.metadata.mds/).
7. The persistent Mach-O binaries (e.g., AccountsHelper, mdworker_shared) are executed to harvest data from browsers, wallets, and system files.
8. Collected data is compressed into out.zip and exfiltrated to the C2 server via HTTP POST requests, with stages categorized by data type (e.g., stage=browsers, stage=wallets).

## Impact

Successful AMOS infection results in the theft of sensitive user data, including stored web browser credentials, cryptocurrency wallet seeds, and Telegram history. The malware's ability to request permissions to the macOS Finder, Desktop, Documents, and Notes applications provides broad access to a victim's personal and work-related files, potentially leading to unauthorized account takeovers and financial loss.

## Recommendation

1. Deploy endpoint monitoring to detect Zsh script execution originating from shell commands containing base64-encoded strings.
2. Implement detection rules for processes creating or modifying files within the ~/Library/Application Support/ directory that share naming conventions with legitimate system services (e.g., .com.apple.accountsd).
3. Block the known malicious C2 infrastructure listed in the IOC table at the network perimeter.
4. Restrict the ability of standard users to execute arbitrary commands from external untrusted websites via Terminal.
