---
title: Abuse of PowerShell Start-BitsTransfer for Data Exfiltration
slug: 2026-10-powershell-bitstransfer
description: Adversaries abuse the PowerShell Start-BitsTransfer cmdlet to facilitate file transfers, enabling clandestine data exfiltration and payload delivery via the Background Intelligent Transfer Service (BITS).
date: "2026-10-12T17:55:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - data-exfiltration
  - persistence
  - command-and-control
  - powershell
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1197
    technique_name: BITS Jobs
    evidence: Start-BitsTransfer can be abused by adversaries to upload sensitive files to remote locations, posing a risk of data loss.
    confidence_band: high
references:
  - https://isc.sans.edu/diary/Investigating+Microsoft+BITS+Activity/23281
  - https://docs.microsoft.com/en-us/windows/win32/bits/using-windows-powershell-to-create-bits-transfer-jobs
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1197/T1197.yaml
rules:
  - title: Detect PowerShell Start-BitsTransfer Execution
    description: Detects the execution of the PowerShell Start-BitsTransfer cmdlet, which is frequently abused for file transfers and data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1197
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
    - action: Deploy the Sigma detection rule to monitor for BITS transfer initiation.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic provided in source content.
  hunt_leads:
    - lead: Search historical logs for PowerShell command lines containing 'Start-BitsTransfer'.
      technique_id: T1197
      data_needed:
        - Command line arguments
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: General abuse vector described in source.
  mitigation_plan:
    - priority: medium
      action: Implement application control or PowerShell Constrained Language Mode to limit unauthorized use of sensitive cmdlets.
      owner: IT Operations
      addresses: T1197
      evidence: Standard security practice for limiting PowerShell abuse.
---

The PowerShell cmdlet `Start-BitsTransfer` is a legitimate administrative tool used for managing file transfers via the Background Intelligent Transfer Service (BITS). However, its capability to move files asynchronously and persistently makes it a prime target for abuse by threat actors. By leveraging BITS, attackers can perform background data exfiltration or download secondary malicious payloads that bypass traditional network inspection or session-based security controls. This technique is frequently observed in malware campaigns, including those associated with Gozi, where BITS jobs are utilized to maintain persistent connectivity or stealthy data movement. Defenders must distinguish between administrative BITS operations and unauthorized process executions, as the service's legitimate use in Windows updates and system management creates a significant source of noise.

## Impact

Successful abuse of `Start-BitsTransfer` can lead to unauthorized exfiltration of sensitive information, potentially compromising intellectual property or personally identifiable information (PII). Furthermore, it provides attackers with a reliable mechanism for persistence and secondary stage delivery, complicating incident response efforts by obfuscating traffic through legitimate Windows system processes.

## Recommendation

* Deploy the Sigma rule below to monitor for `Start-BitsTransfer` execution in your environment, focusing on parent-child process relationships to differentiate between administrative and suspicious activity.
* Ingest full command-line arguments for all PowerShell executions into your SIEM to allow for parsing of file paths used in BITS jobs.
* Baseline legitimate administrative use of BITS in your environment to reduce false positives during incident response.
