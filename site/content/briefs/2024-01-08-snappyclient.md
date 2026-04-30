---
title: SnappyClient Malware Delivered via HijackLoader
slug: 2024-01-08-snappyclient
description: SnappyClient is a multi-functional malware delivered via HijackLoader that steals data from browsers, takes screenshots, logs keystrokes, and establishes a remote terminal for attacker command and control.
date: "2026-03-20T05:19:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - snappyclient
  - hijackloader
  - malware
  - infostealer
  - keylogger
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1056
    technique_name: Input Capture
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1115
    technique_name: Clipboard Data
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rynlw6/technical_analysis_of_snappyclient_delivered/
  - https://www.zscaler.com/blogs/security-research/technical-analysis-snappyclient
rules:
  - title: Detect Screenshot Capture via Cmd
    description: Detects screenshot capture attempts via command line
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1113
    data_sources:
      - process_creation
      - windows
  - title: Detect Keystroke Logging via PowerShell
    description: Detects potential keystroke logging activity using PowerShell.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1056
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

SnappyClient is a sophisticated malware delivered via HijackLoader, a known malware distribution platform. The malware exhibits a wide array of capabilities, indicative of its intent to compromise systems and exfiltrate sensitive data. These capabilities include screenshot capture, keylogging, establishing a remote terminal for interactive command execution, and targeted data theft from web browsers, browser extensions, and other applications. The combination of these functions points towards a threat actor focused on credential harvesting, data collection, and maintaining persistent access through remote command and control. Defenders should prioritize detection and prevention measures to mitigate the risk of SnappyClient infections. The initial report of this activity was published in March 2026.

## Attack Chain

1.  Initial Access: HijackLoader infects the system (delivery mechanism unspecified).
2.  Persistence: HijackLoader establishes persistence to ensure SnappyClient is executed upon system reboot.
3.  Malware Deployment: HijackLoader deploys and executes the SnappyClient malware.
4.  Screenshot Capture: SnappyClient begins capturing screenshots of the user's desktop activity using built-in OS functions.
5.  Keylogging: SnappyClient logs keystrokes to capture sensitive information such as usernames, passwords, and financial details.
6.  Browser Data Theft: SnappyClient targets web browsers and their extensions to steal cookies, saved credentials, and browsing history.
7.  Remote Terminal: SnappyClient establishes a remote terminal, granting the attacker interactive command execution capabilities.
8.  Data Exfiltration: Stolen data is exfiltrated to a command and control server controlled by the attacker.

## Impact

Successful SnappyClient infections can result in significant data breaches, including the compromise of sensitive credentials, financial information, and personal data. The remote terminal functionality allows attackers to perform arbitrary actions on compromised systems, potentially leading to further damage or lateral movement within the network. While the number of victims and specific sectors targeted are unknown, the malware's capabilities make it a high-risk threat to organizations of all sizes.

## Recommendation

*   Enable Sysmon process-creation logging to enhance visibility into HijackLoader and SnappyClient execution (logsource: process_creation).
*   Implement network monitoring to detect and block connections to known HijackLoader command and control infrastructure.
*   Deploy the Sigma rules in this brief to your SIEM to detect SnappyClient activity and tune for your environment.
*   Monitor registry modifications for persistence mechanisms used by HijackLoader to launch SnappyClient (logsource: registry_set).
