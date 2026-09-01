---
title: Detection of PowerShell Web Request Commands via ScriptBlock Logging
slug: 2026-09-web-request-cmdlets
description: This brief documents the usage of PowerShell cmdlets and command-line tools for web-based data retrieval, often leveraged by attackers for stage-two payload delivery or data exfiltration.
date: "2026-09-01T12:19:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - powershell
  - reconnaissance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_web_request_cmd_and_cmdlets.yml
  - https://4sysops.com/archives/use-powershell-to-download-a-file-with-http-https-and-ftp/
  - https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell
rules:
  - title: Usage Of Web Request Commands And Cmdlets - ScriptBlock
    description: Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets via PowerShell scriptblock logs
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event 4104) on critical assets.
      owner: IT Operations
      due: 72h
      evidence: Log source requirements specified in rule metadata.
  hunt_leads:
    - lead: Search for high-frequency usage of iwr/Invoke-WebRequest from non-administrative service accounts.
      technique_id: T1059.001
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source documents these as primary vectors for web requests.
---

Attackers frequently utilize built-in Windows PowerShell cmdlets and command-line utilities to perform web requests, facilitating the download of malicious payloads or the exfiltration of sensitive data. Because these utilities are native to the Windows environment, they are often used as living-off-the-land techniques to blend in with legitimate administrative activity. PowerShell ScriptBlock logging provides visibility into the execution of these commands even when aliases are used. Monitoring for specific commands such as Invoke-WebRequest, Invoke-RestMethod, BitsTransfer, and third-party tools like curl and wget allows security operations teams to detect suspicious external network interactions initiated by PowerShell.

## Impact

Successful abuse of these cmdlets can lead to unauthorized code execution, the introduction of secondary malware, and the exfiltration of internal data to attacker-controlled infrastructure. These techniques are common in both initial stage deployment and post-exploitation command-and-control communication.

## Recommendation

1. Enable PowerShell ScriptBlock Logging (Event ID 4104) across all Windows endpoints to capture full script content.
2. Deploy the provided Sigma rule to your SIEM to monitor for suspicious web request activity.
3. Establish a baseline for legitimate administrative scripts that utilize these cmdlets and add them to the filter block to reduce false positives.
4. Integrate the identified cmdlets and command aliases into your threat hunting program to investigate anomalous external network connections originating from non-browser processes.
