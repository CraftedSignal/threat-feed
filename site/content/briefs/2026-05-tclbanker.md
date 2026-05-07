---
title: TCLBanker Banking Trojan Self-Spreads via WhatsApp and Outlook
slug: 2026-05-tclbanker
description: TCLBanker is a banking trojan targeting 59 financial platforms, spreading via trojanized Logitech AI Prompt Builder installers and worm modules for WhatsApp and Outlook, enabling remote control and data theft.
date: "2026-05-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - banking-trojan
  - malware
  - worm
  - self-spreading
  - brazil
  - logitech
vendors:
  - Logitech
  - Microsoft
  - Chromium
  - Elastic
products:
  - AI Prompt Builder
  - Microsoft Outlook
  - Chromium browser
  - WhatsApp Web
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: 'Phishing: Spearphishing Attachment'
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204.002
    technique_name: 'User Execution: Malicious File'
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1056.001
    technique_name: 'Input Capture: Keylogging'
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087.001
    technique_name: 'Account Discovery: Local Account'
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.bleepingcomputer.com/news/security/new-tclbanker-malware-self-spreads-over-whatsapp-and-outlook/
rules:
  - title: Detect Suspicious MSI Installer Execution
    description: Detects suspicious execution of MSI installers that could indicate a trojanized installer like the one used by TCLBanker.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Outlook COM Hijacking
    description: Detects suspicious processes spawning from Outlook using COM automation, which may indicate malware abusing Outlook to spread.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1059.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

TCLBanker is a newly discovered banking trojan targeting 59 banking, fintech, and cryptocurrency platforms. Discovered by Elastic Security Labs in May 2026, TCLBanker is believed to be an evolution of the Maverick/Sorvepotel malware family. The initial infection vector involves a trojanized MSI installer for Logitech AI Prompt Builder. Once installed, TCLBanker exhibits worm-like behavior, self-spreading through WhatsApp and Microsoft Outlook to propagate to new victims. While currently focused on Brazilian targets, its potential to expand geographically poses a significant risk. TCLBanker is heavily protected against analysis, actively monitoring for debugging and analysis tools. The malware leverages DLL side-loading within the legitimate Logitech application to evade initial detection.

## Attack Chain

1.  The victim downloads and executes a trojanized MSI installer for Logitech AI Prompt Builder.
2.  The installer performs DLL side-loading to inject the TCLBanker malware into the legitimate Logitech application process.
3.  TCLBanker monitors the browser address bar using Windows UI Automation APIs, searching for URLs matching its 59 targeted financial platforms.
4.  When a targeted website is accessed, TCLBanker establishes a WebSocket session with its command-and-control (C2) server, sending victim and system information.
5.  The C2 operator gains remote control capabilities, including live screen streaming, screenshot capturing, keylogging, clipboard hijacking, shell command execution, and file system access.
6.  TCLBanker uses a WPF-based overlay system to display fake credential prompts, PIN keypads, and other deceptive overlays to steal sensitive information.
7.  The malware hijacks the victim's WhatsApp account by searching for authenticated WhatsApp Web IndexedDB data in Chromium browser profiles and launching a hidden Chromium instance to send spam messages to contacts, filtering for Brazilian numbers.
8.  TCLBanker abuses Microsoft Outlook through COM automation to harvest contacts and sender addresses, sending phishing emails from the victim's email account to further spread the malware.

## Impact

TCLBanker enables attackers to steal banking credentials, cryptocurrency wallet information, and other sensitive data from victims. It also allows for remote control of infected systems, enabling attackers to perform unauthorized actions, potentially leading to financial loss, identity theft, and further propagation of the malware. The self-spreading capabilities via WhatsApp and Outlook significantly increase the malware's reach, potentially impacting a large number of individuals and organizations, especially those operating in Brazil.

## Recommendation

*   Monitor process creations for suspicious instances of `msiexec.exe` installing software from untrusted sources (see Sigma rule: "Detect Suspicious MSI Installer Execution").
*   Enable Sysmon process creation logging to detect DLL side-loading activity from legitimate applications like the Logitech AI Prompt Builder process, potentially indicating TCLBanker infection.
*   Monitor network connections for WebSocket traffic originating from systems running legitimate applications that should not be communicating over websockets to external addresses.
*   Implement network detections for outbound email traffic containing suspicious attachments or links originating from user accounts that have not recently logged into Outlook (see Sigma rule "Detect Outlook COM Hijacking").
