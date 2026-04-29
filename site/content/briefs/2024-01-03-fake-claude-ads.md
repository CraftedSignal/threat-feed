---
title: Malware Spreading Through Fake 'Claude Code' Google Ads
slug: 2024-01-03-fake-claude-ads
description: Malware is distributed via malicious advertisements on Google impersonating 'Claude Code', targeting both Windows and macOS operating systems with the goal of infecting users.
date: "2026-03-15T15:31:12Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - malware
  - google_ads
  - initial_access
  - windows
  - macos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.reddit.com/r/blueteamsec/comments/1ruh0r8/windows_and_macos_malware_spreads_via_fake_claude/
  - https://www.bitdefender.com/en-us/blog/labs/fake-claude-code-google-ads-malware
rules:
  - title: Detect Web Requests to Sites with Claude in the Domain
    description: Detects web requests to domains containing 'claude' which may indicate malicious activity related to the Claude code malware campaign.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - web_proxy
      - windows|linux|macos
  - title: Detect Execution of Downloaded Files from Suspicious Domains
    description: Detects execution of files downloaded from domains potentially associated with the Claude code malware campaign.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A malware campaign is underway, leveraging deceptive advertisements on Google that masquerade as legitimate 'Claude Code' software. The attackers are using these ads to direct unsuspecting users to malicious websites hosting malware payloads for both Windows and macOS systems. While specific details on the malware are limited, the campaign's reliance on search engine advertisement poisoning indicates a broad targeting strategy aimed at users actively seeking 'Claude Code' related software or tools. This campaign highlights the increasing sophistication of threat actors in using search engine optimization (SEO) poisoning techniques to distribute malware. Defenders should be aware of the potential for users to be directed to malicious sites through search results.

## Attack Chain

1.  The attacker creates malicious advertisements on Google that mimic legitimate 'Claude Code' software or related tools.
2.  Users searching for 'Claude Code' or related terms encounter the malicious advertisements in their search results.
3.  Unsuspecting users click on the malicious advertisement, believing it to be a legitimate source for 'Claude Code'.
4.  The advertisement redirects the user to a malicious website controlled by the attacker.
5.  The malicious website hosts malware payloads tailored for both Windows and macOS operating systems.
6.  Upon visiting the site, the user is tricked into downloading and executing the malware, potentially through social engineering or drive-by download techniques.
7.  The malware executes on the victim's system, establishing persistence and potentially disabling security controls.
8.  The malware performs its intended malicious activities, such as data theft, credential harvesting, or further malware deployment.

## Impact

The impact of this campaign could be widespread, affecting both individual users and organizations who rely on 'Claude Code'. Successful infection can lead to data theft, financial loss, and reputational damage. Given the use of Google Ads, the number of potential victims is substantial. The cross-platform nature of the attack further amplifies the risk, as it targets a broader range of users regardless of their operating system.

## Recommendation

*   Implement browser security extensions and ad blockers to reduce the likelihood of users clicking on malicious advertisements.
*   Educate users about the risks of clicking on advertisements in search results and encourage them to verify the legitimacy of websites before downloading software.
*   Monitor network traffic for connections to newly registered domains or known malicious IP addresses associated with malware distribution.
*   Deploy endpoint detection and response (EDR) solutions to detect and prevent malware execution on both Windows and macOS systems.
*   Enable and review web proxy logs for user visits to suspicious domains.
*   Configure intrusion detection systems (IDS) to identify and block malicious traffic originating from advertisement networks.
