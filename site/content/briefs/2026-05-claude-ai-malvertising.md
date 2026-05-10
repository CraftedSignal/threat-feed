---
title: Malvertising Campaign Abuses Google Ads and Claude.ai for macOS Malware Delivery
slug: 2026-05-claude-ai-malvertising
description: Attackers are using Google Ads malvertising and weaponized Claude.ai shared chats to trick macOS users into downloading and executing malware, leading to credential theft and system compromise.
date: "2026-05-10T17:54:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - malvertising
  - macos
  - infostealer
  - googleads
  - claudeai
vendors:
  - Google
  - Anthropic
  - Apple
products:
  - Google Ads
  - Claude.ai
affected_os:
  - MacOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://www.bleepingcomputer.com/news/security/hackers-abuse-google-ads-claudeai-chats-to-push-mac-malware/
iocs:
  - type: domain
    value: customroofingcontractors[.]com
  - type: domain
    value: bernasibutuwqu2[.]com
  - type: domain
    value: briskinternet[.]com
ioc_counts:
  domain: 3
rules:
  - title: Detect Suspicious macOS Shell Script Downloads
    description: Detects suspicious shell script downloads on macOS systems, often indicative of malware installation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - macos
  - title: Detect macOS osascript Execution of Suspicious Payloads
    description: Detects the execution of suspicious payloads via the osascript command on macOS, indicating potential malware activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - macos
  - title: Detect MacSync Infostealer Activity
    description: Detects potential MacSync infostealer activity by monitoring for exfiltration traffic to known C2 domains
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - macos
rules_count: 3
---

An active malvertising campaign is leveraging Google Ads and the shared chat functionality of the Claude.ai platform to distribute macOS malware. The attackers create Google Ads that appear when users search for "Claude mac download," leading victims to a genuine claude.ai link. However, this link points to a malicious shared chat presenting itself as an official "Claude Code on Mac" installation guide attributed to "Apple Support."  The guide tricks users into copying and pasting a command into their terminal that downloads and executes a shell script. Two variants of the attack have been observed using different infrastructure. The malware exfiltrates browser credentials, cookies, and macOS Keychain contents. This campaign, observed in May 2026, highlights the increasing sophistication of social engineering tactics used to bypass traditional security measures by abusing legitimate services.

## Attack Chain

1.  The attacker creates a malicious Google Ad targeting users searching for "Claude mac download."
2.  The victim clicks on the ad, which leads to a legitimate claude.ai URL hosting a malicious shared chat.
3.  The Claude.ai shared chat poses as an official installation guide for "Claude Code on Mac," falsely attributed to Apple Support.
4.  The chat instructs the user to open Terminal and paste a base64 encoded command.
5.  The base64 command decodes to a shell script that downloads another shell script (loader.sh) from a remote server (e.g., bernasibutuwqu2[.]com or customroofingcontractors[.]com).
6.  The loader.sh script may perform victim profiling, such as checking for Russian/CIS keyboard layouts and collecting external IP, hostname, OS version, and keyboard locale.
7.  The script downloads and executes a second-stage payload using osascript, enabling remote code execution.
8.  The second-stage payload (MacSync variant) harvests browser credentials, cookies, and macOS Keychain contents and exfiltrates them to the attacker's server, potentially briskinternet[.]com.

## Impact

Successful exploitation leads to the compromise of macOS systems, with attackers gaining access to sensitive user credentials, cookies, and keychain data. This stolen information can be used for identity theft, financial fraud, and further access to other systems and services. The campaign demonstrates the effectiveness of using trusted platforms like Claude.ai to distribute malware and bypass user suspicion. The number of affected victims is currently unknown.

## Recommendation

*   Deploy the Sigma rule "Detect Suspicious macOS Shell Script Downloads" to identify suspicious shell script downloads from uncommon locations (reference rule below).
*   Block the identified malicious domains (customroofingcontractors[.]com, bernasibutuwqu2[.]com, and briskinternet[.]com) at the DNS resolver or firewall to prevent malware downloads and exfiltration (reference IOC list).
*   Educate users to exercise caution when following instructions from shared chats or sponsored search results, especially those involving pasting commands into the terminal.
*   Implement browser security policies to prevent credential theft and cookie exfiltration.
