---
title: Microsoft 365 Copilot Jailbreak Attempts via Prompt Injection
slug: 2024-01-03-m365-copilot-jailbreak
description: This detection identifies Microsoft 365 Copilot jailbreak attempts by detecting prompt injection techniques within exported eDiscovery prompt logs to circumvent built-in safety controls.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prompt-injection
  - jailbreak
  - microsoft365
vendors:
  - Microsoft
products:
  - Microsoft 365 Copilot
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.splunk.com/en_us/blog/artificial-intelligence/m365-copilot-log-analysis-splunk.html
rules:
  - title: Detect M365 Copilot Jailbreak Attempts via Keyword Matching
    description: Detects attempts to jailbreak M365 Copilot by searching for specific keywords indicative of prompt injection in the Subject_Title field of eDiscovery prompt logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
      - windows
  - title: Detect M365 Copilot Amoral Impersonation Jailbreak
    description: Detects attempts to jailbreak M365 Copilot by using amoral impersonation requests.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
      - windows
rules_count: 2
---

This threat brief addresses the risk of prompt injection attacks targeting Microsoft 365 Copilot. Attackers attempt to bypass safety controls and manipulate the AI's behavior through crafted prompts. The attacks leverage techniques such as rule manipulation, system bypass commands, and AI impersonation requests. Defenders need to monitor for these jailbreak attempts because successful prompt injections could lead to data exfiltration, policy violations, or other unauthorized activities within the M365 environment. The detection focuses on analyzing exported eDiscovery prompt logs, specifically the Subject_Title field, to identify prompts containing jailbreak keywords.

## Attack Chain

1.  Attacker crafts a malicious prompt containing jailbreak keywords (e.g., "pretend you are", "act as", "rules=", "ignore", "bypass", "override").
2.  The attacker submits the crafted prompt to Microsoft 365 Copilot.
3.  The prompt is processed by Copilot, and an entry is logged in the M365 eDiscovery prompt logs, including the prompt text in the Subject_Title field.
4.  An analyst exports the M365 eDiscovery prompt logs from the Microsoft Purview compliance portal.
5.  The exported logs are ingested into a security information and event management (SIEM) system for analysis.
6.  The SIEM searches the Subject_Title field for jailbreak keywords.
7.  A risk score is assigned to the prompt based on the type of manipulation attempted.
8.  If the jailbreak score meets or exceeds a predefined threshold, an alert is triggered.

## Impact

Successful prompt injection attacks on Microsoft 365 Copilot can lead to various negative consequences, including data exfiltration, unauthorized access to sensitive information, violation of acceptable use policies, and the potential for the AI to generate harmful or misleading content. The number of victims depends on the scope of the compromised Copilot instance and the attacker's objectives. The sectors targeted would be any utilizing M365 Copilot.

## Recommendation

*   Configure Microsoft Purview eDiscovery to export M365 Copilot prompt logs to a SIEM for analysis as described in the "how_to_implement" section of the source detection.
*   Deploy the provided Sigma rules to your SIEM to detect jailbreak attempts based on prompt injection techniques, tuning the threshold based on your environment.
*   Investigate triggered alerts, focusing on prompts with high jailbreak scores, to assess the potential impact and implement appropriate remediation measures.
*   Review and update M365 Copilot acceptable use policies to explicitly address the risks associated with prompt injection attacks.
