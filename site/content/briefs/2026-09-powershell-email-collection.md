---
title: PowerShell Local Email Collection Techniques
slug: 2026-09-powershell-email-collection
description: Adversaries use PowerShell scripts leveraging Outlook COM objects to programmatically access and exfiltrate user email data from local systems.
date: "2026-09-03T13:42:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - collection
  - powershell
  - outlook
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
    evidence: Files containing email data can be acquired from a users local system, such as Outlook storage or cache files.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_mail_acces.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1114.001/T1114.001.md
rules:
  - title: Detect PowerShell Outlook Email Collection
    description: Detects PowerShell scripts utilizing Outlook COM objects or interop libraries for local email access
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1114.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging across all endpoints
      owner: IT Operations
      due: 72h
      evidence: Log source requirements specified in the Sigma rule
  hunt_leads:
    - lead: Search for historical Event ID 4104 entries containing 'outlook.application'
      technique_id: T1114.001
      data_needed:
        - Powershell Script Block Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source provides specific command strings often used in malicious scripts
---

Adversaries frequently target local email storage to collect sensitive information, leveraging the legitimate capabilities of the Microsoft Outlook COM interface via PowerShell. By interfacing with the Outlook Application object, attackers can programmatically navigate folder structures, such as the Inbox, to extract messages and attachments without direct user interaction. This technique is often used in the post-compromise stage to gain access to corporate communications, credentials, or sensitive project files. Because this activity utilizes built-in automation features, it is often difficult to distinguish from legitimate administrative scripts or automated tools. Defenders should prioritize visibility into PowerShell Script Block Logging to detect the instantiation of the Outlook COM object or the usage of specific Outlook interop libraries in non-standard contexts.

## Impact

Successful execution allows attackers to exfiltrate historical email correspondence and attachments, potentially leading to identity theft, corporate espionage, or the acquisition of further credentials to facilitate lateral movement. This poses a high risk to information confidentiality within any organization utilizing Microsoft Outlook on Windows endpoints.

## Recommendation

1. Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to capture script execution content.
2. Deploy the provided Sigma rule to detect the initiation of Outlook COM objects or the use of Outlook interop libraries in PowerShell scripts.
3. Monitor for unauthorized or unknown scripts performing collection tasks on local storage paths associated with Outlook profiles.
