---
title: Detection of PowerShell Downloads from Code Hosting Services
slug: 2026-10-powershell-code-hosting-download
description: This detection identifies PowerShell activity using native cmdlets to fetch payloads from raw-content URLs on code hosting platforms, a technique frequently abused for stage-one payload delivery.
date: "2026-10-19T02:51:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - powershell
  - staging
  - initial-access
  - code-hosting
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This analytic detects PowerShell Script Block Logging (Event ID 4104) events that use common download methods.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: A match identifies a download attempt; it does not establish that the file was successfully retrieved or executed.
    confidence_band: high
rules:
  - title: Detect PowerShell Download from Code Hosting Service
    description: Detects PowerShell script blocks using common download cmdlets to retrieve executable or script files from raw URLs on GitHub, GitLab, or Codeberg.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.001
      - T1105
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into script block activity
    - action: Deploy the Detection Rule to SIEM for monitoring
      owner: Detection Engineering
      due: 48h
      evidence: Analytic supports identification of T1059.001 and T1105
  hunt_leads:
    - lead: Search for script blocks containing both download cmdlets and github/gitlab/codeberg URL patterns
      technique_id: T1105
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source analytic search criteria
---

Threat actors frequently abuse legitimate code hosting services like GitHub, GitLab, and Codeberg to stage and retrieve malicious payloads. By hosting payloads as "raw" content, attackers can use native Windows PowerShell cmdlets to download and execute scripts or binaries directly into memory or to disk, bypassing traditional perimeter defenses that might block unknown web domains. This activity is often associated with initial access or delivery stages of malware campaigns, including the Braodo Stealer. Detection engineers must distinguish between legitimate administrative tasks or developer workflows and unauthorized staging of executable content by correlating the PowerShell script block with the process ancestry, the destination path, and the file type retrieved.

## Impact

Successful exploitation of this technique allows attackers to stage and execute malicious payloads within an environment. If unauthorized scripts (such as .ps1, .bat) or binaries (.exe, .dll) are retrieved and executed, it can lead to credential theft, persistence establishment, or full system compromise. The severity of the impact depends on the nature of the staged payload and the permissions of the account executing the script.

## Recommendation

Prioritize the identification of unauthorized downloads from code hosting services by monitoring PowerShell Script Block Logging.

* Enable PowerShell Script Block Logging (Event ID 4104) and ensure the `ScriptBlockText` field is ingested into the SIEM.
* Deploy the provided Sigma rule to detect common PowerShell download patterns directed at GitHub, GitLab, or Codeberg raw content URLs.
* Review administrative and developer workstation baseline activity to reduce noise from legitimate script and package management workflows.
