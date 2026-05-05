---
title: Suspicious WMIC Application Uninstallation
slug: 2024-01-wmic-uninstallation
description: This analytic identifies the use of the WMIC command-line tool to uninstall applications non-interactively, a technique used to evade detection by removing security software, as observed in IcedID campaigns.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - IcedID
tags:
  - defense-evasion
  - application-uninstall
  - wmic
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
references:
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
rules:
  - title: Suspicious WMIC Product Uninstall via CommandLine
    description: Detects the use of wmic.exe to uninstall applications in a non-interactive manner, which is often used by malware to remove security products.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Suspicious WMIC Process Spawning
    description: Detects suspicious processes spawning wmic.exe
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection focuses on the abuse of Windows Management Instrumentation Command-line (WMIC) to uninstall applications in a non-interactive manner. This technique is often employed by threat actors, including IcedID, to disable or remove security software, such as antivirus solutions, in order to evade detection and establish a stronger foothold within a compromised environment. This activity is often seen post-compromise, after initial access has been established, and is used to further the attacker's objectives. The use of the `/nointeractive` flag is a key indicator of this malicious activity. This behavior is significant because it allows attackers to disable security defenses, facilitating further compromise and persistence within the environment.

## Attack Chain

1. Initial access is gained through a phishing campaign or other exploit.
2. The attacker executes a malicious payload on the victim machine.
3. The payload establishes persistence and elevates privileges.
4. WMIC is invoked via `wmic.exe` with parameters to enumerate installed products.
5. The attacker uses the `product` argument with a `where name` clause to identify target applications.
6. WMIC is then used with the `call uninstall` command to remove the target application.
7. The `/nointeractive` flag is used to suppress prompts and execute the uninstall silently.
8. Security software is disabled, allowing for further malicious activity.

## Impact

Successful execution of this attack results in the removal of security software, such as antivirus or endpoint detection and response (EDR) agents, which significantly reduces the victim's ability to detect and respond to the compromise. As seen in the IcedID campaign, this can lead to rapid escalation, such as ransomware deployment within 24 hours. This can affect any Windows environment where WMIC is accessible, potentially impacting organizations of any size.

## Recommendation

*   Deploy the Sigma rule `Suspicious WMIC Product Uninstall via CommandLine` to detect non-interactive uninstallation attempts.
*   Investigate any process that spawns `wmic.exe` with arguments containing `product`, `where name`, `call uninstall`, and `/nointeractive`, as highlighted in the rule description.
*   Ensure endpoint detection and response (EDR) agents are configured to log process command-line arguments, which is required for the detection to function correctly.
*   Review and harden endpoint security policies to restrict the use of WMIC where possible.
*   Monitor parent processes of `wmic.exe` to identify potential malicious origins.
*   Whitelist legitimate uses of `wmic.exe` for application uninstallation, based on parent process and command line, to reduce false positives.
