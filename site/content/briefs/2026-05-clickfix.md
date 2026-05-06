---
title: ClickFix Campaign Targets macOS Users with Infostealers via Fake Utility Fixes
slug: 2026-05-clickfix
description: The ClickFix campaign targets macOS users with fake utility fixes, tricking them into running malicious Terminal commands to install infostealing malware such as Macsync, Shub Stealer, and AMOS.
date: "2026-05-06T15:20:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - macos
  - infostealer
  - clickfix
  - terminal
vendors:
  - Microsoft
  - Squarespace
  - Craft
  - Medium
products:
  - Microsoft Security Blog
  - Craft
  - Medium
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/
iocs:
  - type: domain
    value: domenpozh[.]net
  - type: domain
    value: mac-storage-guide.squarespace[.]com
  - type: domain
    value: macclean[.]craft[.]me
  - type: domain
    value: macos-disk-space[.]medium[.]com
  - type: domain
    value: t[.]me/ax03bot
ioc_counts:
  domain: 5
rules:
  - title: Detect Suspicious macOS Terminal Command Chains
    description: Detects suspicious command chains in macOS Terminal that download and execute remote scripts, potentially indicating ClickFix activity.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - macos
  - title: Detect macOS Process Spawning from /tmp
    description: Detects processes executing directly from the /tmp directory, which is often used by malware to drop and execute payloads.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

The ClickFix campaign is an ongoing threat targeting macOS users by employing social engineering techniques to deliver infostealing malware. Since at least February 2026, threat actors have been observed hosting malicious commands on various platforms, including blog sites and content creation platforms, disguised as macOS utility fixes (e.g., disk space optimization). These commands, when executed by unsuspecting users, lead to the installation of infostealers such as Macsync, Shub Stealer, and AMOS. These malware variants collect and exfiltrate sensitive data, including media files, iCloud data, Keychain entries, and cryptocurrency wallets. Some campaigns also replace legitimate cryptocurrency wallet applications with trojanized versions, further compromising user security. This campaign represents a shift from previous tactics involving disk image files to a more direct approach leveraging Terminal commands and native macOS utilities to bypass traditional security checks like Gatekeeper.

## Attack Chain

1.  The attacker hosts malicious commands on websites, blog posts, or content platforms disguised as macOS utility fixes.
2.  The user is tricked into copying and pasting a malicious command into the macOS Terminal.
3.  The Terminal command executes a script, often Base64-encoded, which retrieves a remotely hosted payload using `curl`.
4.  The downloaded payload, a shell script, is executed.  This script performs reconnaissance by collecting system information (keyboard layout, hostname, OS version, IP address).
5.  The script checks for Russian/CIS keyboard layouts as a kill switch; if detected, execution halts.
6.  If the kill switch is not activated, the script downloads and executes an AppleScript payload directly in memory using `osascript`.
7.  The AppleScript payload steals credentials, cryptocurrency wallet data, and other sensitive information.
8.  The stolen data is exfiltrated to attacker-controlled servers via HTTP POST requests.

## Impact

The ClickFix campaign poses a significant threat to macOS users, potentially leading to the theft of sensitive personal and financial information. Victims who execute the malicious commands risk losing credentials, iCloud data, cryptocurrency holdings, and other valuable data. The campaign's use of trojanized cryptocurrency wallet apps adds an additional layer of risk, potentially leading to further financial losses. While the total number of victims is unknown, the widespread nature of the campaign and the use of popular platforms like Medium suggest a potentially large impact.

## Recommendation

*   Deploy the Sigma rule "Detect Suspicious macOS Terminal Command Chains" to identify command-line execution patterns indicative of the ClickFix campaign.
*   Block the C2 domains and IP addresses listed in the IOC table at the network perimeter to prevent communication with attacker infrastructure.
*   Monitor process creation events for `osascript` executing downloaded scripts, as detailed in the "AppleScript infostealer" section.
*   Educate users about the risks of copying and pasting commands from untrusted sources into the Terminal.
*   Implement application control policies to prevent the execution of unauthorized applications and scripts.
