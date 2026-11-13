---
brief_id: brief-2026-11-13-powershell-start-bitstransfer
event_id: brief-2026-11-13-powershell-start-bitstransfer
revision: 1
activity_at: "2026-11-13T17:37:38Z"
title: PowerShell Start-BitsTransfer Abuse Detection
slug: 2026-11-powershell-start-bitstransfer
description: This detection monitors for malicious abuse of the Background Intelligent Transfer Service (BITS) via PowerShell's Start-BitsTransfer cmdlet, often used by attackers for file staging, payload downloading, or exfiltration.
date: "2026-11-13T17:37:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - defense-evasion
  - persistence
  - command-and-control
  - powershell
  - bits
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1197
    technique_name: BITS Jobs
    evidence: The analytic detects PowerShell command lines initiating a BITS transfer which is a known technique for bypassing perimeter defenses.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Attackers leverage BITS to download malicious payloads.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/powershell_start_bitstransfer.yml
  - https://isc.sans.edu/diary/Investigating+Microsoft+BITS+Activity/23281
  - https://learn.microsoft.com/en-us/powershell/module/bitstransfer/start-bitstransfer
rules:
  - title: Detect PowerShell Start-BitsTransfer Abuse
    description: Detects usage of the Start-BitsTransfer cmdlet with suspicious destinations (IPs, file-sharing sites) or suspicious local staging of executable files.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1105
      - T1197
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided detection to monitor for suspicious BITS usage patterns.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for unusual child processes or immediate execution following a Start-BitsTransfer command.
      technique_id: T1197
      data_needed:
        - Sysmon Event ID 1
        - Process Creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The detection logic specifically highlights chained execution commands like Start-Process or Invoke-Expression as a behavioral indicator.
---

Attackers frequently abuse the Windows Background Intelligent Transfer Service (BITS) to download malicious payloads or stage data for exfiltration, taking advantage of its ability to run asynchronously and often bypassing simple firewall rules. The Start-BitsTransfer PowerShell cmdlet is a native utility that can be weaponized for these purposes. This detection identifies suspicious usage of this cmdlet by monitoring for transfers to known public file-sharing services, direct IP addresses, or transfers targeting high-risk local directories with executable extensions, as well as those followed by immediate execution commands.

## Impact

Abuse of BITS can lead to silent malware delivery, persistence, or data exfiltration. Because BITS activity is often handled by a system process, it can successfully evade some perimeter defenses that are tuned only for common browser-based or shell-based download activity.

## Recommendation

Deploy the provided detection logic to identify potential BITS abuse. Given the potential for false positives from legitimate administrative or CI/CD tasks, tune the filters to exclude known-good internal staging directories and authorized service accounts.
