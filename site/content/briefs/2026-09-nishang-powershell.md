---
title: Detection of Nishang Exploitation Framework PowerShell Cmdlets
slug: 2026-09-nishang-powershell
description: This brief documents detection signatures for the Nishang offensive PowerShell framework, a collection of scripts used for post-exploitation, lateral movement, and credential theft.
date: "2026-09-03T12:36:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - offensive-tool
  - post-exploitation
  - powershell
  - detection
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The framework utilizes PowerShell commandlets to perform malicious activities as part of the execution phase.
    confidence_band: high
references:
  - https://github.com/samratashok/nishang
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_nishang_malicious_commandlets.yml
rules:
  - title: Detect Malicious Nishang PowerShell Cmdlets
    description: Detects the execution of known Nishang framework cmdlet names via PowerShell Script Block Logging
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104)
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into script block content
  hunt_leads:
    - lead: Search for specific Nishang cmdlets in historical PowerShell logs
      technique_id: T1059.001
      data_needed:
        - Event ID 4104
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Nishang cmdlets indicate potential post-exploitation activity
---

Nishang is a well-known open-source framework consisting of a collection of PowerShell scripts and payloads designed for offensive security testing. Attackers frequently leverage Nishang's cmdlets to perform post-exploitation tasks, including credential harvesting, lateral movement, backdoor deployment, and data exfiltration. The framework's utility stems from its ability to reside entirely in memory, evading traditional disk-based detection. Defenders must prioritize monitoring PowerShell Script Block Logging to identify the execution of these specific cmdlets, which often indicate an active compromise rather than routine administrative activity. The framework includes diverse capabilities ranging from shellcode injection to the creation of malicious Office documents and persistence mechanisms.

## Attack Chain

1. Initial access via phishing or vulnerability exploitation (e.g., remote code execution).
2. Execution of a stager payload to establish a PowerShell session.
3. Bypassing execution policies or AMSI using scripts such as Invoke-AmsiBypass.
4. Credential harvesting using modules like DumpCreds, DumpHashes, or Get-Web-Credentials.
5. Lateral movement through remote WMI or PSRemoting via Set-RemoteWMI or Set-RemotePSRemoting.
6. Deployment of backdoors such as HTTP-Backdoor or constrained delegation modifications.
7. Data exfiltration using Do-Exfiltration-Dns or custom DNS TXT queries.
8. Final objective achieved (e.g., domain dominance, data theft).

## Impact

Successful utilization of the Nishang framework can lead to full system compromise, credential theft, and persistent unauthorized access within a target environment. Organizations in all sectors are targets as these tools are generic post-exploitation utilities used by a wide variety of threat actors.

## Recommendation

- Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to capture script execution content.
- Deploy the provided Sigma rule to your SIEM to monitor for the specific Nishang cmdlets documented in this brief.
- Proactively hunt for Nishang usage in existing logs to identify potentially compromised internal hosts.
- Implement constrained language mode (CLM) for non-administrative users to limit the effectiveness of PowerShell-based offensive tools.
