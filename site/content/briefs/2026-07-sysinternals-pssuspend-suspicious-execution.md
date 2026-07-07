---
title: Sysinternals PsSuspend Suspicious Execution to Impair Defenses
slug: 2026-07-sysinternals-pssuspend-suspicious-execution
description: Adversaries are leveraging the legitimate Sysinternals PsSuspend utility to suspend critical security processes, such as Microsoft Defender Antivirus (`msmpeng.exe`), as a defense impairment technique to bypass endpoint detection and response (EDR) solutions.
date: "2026-07-03T14:29:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - utility
  - sysinternals
  - windows
vendors:
  - Microsoft
products:
  - Sysinternals PsSuspend
affected_os:
  - Windows
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/pssuspend
  - https://twitter.com/0gtweet/status/1638069413717975046
rules:
  - title: Sysinternals PsSuspend Suspicious Execution
    description: Detects the suspicious execution of Sysinternals PsSuspend to suspend critical security processes, such as msmpeng.exe (Microsoft Defender Antivirus service), indicating an attempt to impair defenses.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Threat actors are increasingly misusing legitimate system utilities, like Microsoft's Sysinternals PsSuspend, to hinder security defenses. PsSuspend is a powerful tool designed for administrators to pause and resume processes on local or remote systems. However, its capability to suspend any running process, including critical antivirus (AV) and endpoint detection and response (EDR) agents, makes it an attractive target for adversaries seeking to operate undetected. This brief highlights the detection of PsSuspend being executed with command-line arguments targeting security processes such as `msmpeng.exe` (Microsoft Defender Antivirus service). Such activity indicates an attempt to temporarily disable or bypass security controls, allowing subsequent malicious activity to proceed without interference. While the exact campaigns are not specified in the source, this technique is broadly adopted by various sophisticated threat groups for defense evasion.

## Attack Chain

[Insufficient information in the provided source to construct a detailed 6-8 step attack chain covering initial access through impact. The source describes a single defense impairment action rather than a full campaign lifecycle.]

## Impact

Successful execution of PsSuspend against security processes can lead to a critical blind spot in an organization's defense posture. When AV/EDR agents are suspended, they cease to monitor, detect, and prevent malicious activities, effectively disarming endpoint protection. This allows threat actors to perform actions such as executing malware, establishing persistence, exfiltrating data, or deploying ransomware without being detected. The immediate consequence is a loss of visibility and control, significantly increasing the risk of a successful breach and subsequent data compromise or system disruption.

## Recommendation

*   Deploy the provided Sigma rule "Sysinternals PsSuspend Suspicious Execution" to your SIEM and tune for your environment to detect attempts to suspend security products.
*   Ensure process creation logging, especially for command-line arguments, is enabled on all Windows endpoints to support the detection rules.
*   Restrict the execution of unauthorized or unapproved system utilities, including Sysinternals tools, on critical endpoints.
*   Implement strong access controls and principle of least privilege to prevent unauthorized users or processes from running tools like PsSuspend.
