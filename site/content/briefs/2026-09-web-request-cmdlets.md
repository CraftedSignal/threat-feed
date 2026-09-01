---
title: Detection of Suspicious Web Request Execution via PowerShell and CLI
slug: 2026-09-web-request-cmdlets
description: This brief documents detection logic for identifying potential malicious file downloads and C2 communication using native Windows command-line tools and PowerShell cmdlets.
date: "2026-09-01T12:25:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - detection-engineering
  - windows
  - execution
  - living-off-the-land
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets (including aliases) via CommandLine.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_web_request_cmd_and_cmdlets.yml
  - https://4sysops.com/archives/use-powershell-to-download-a-file-with-http-https-and-ftp/
  - https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell
  - https://learn.microsoft.com/en-us/powershell/module/bitstransfer/add-bitsfile?view=windowsserver2019-ps
rules:
  - title: Detect Usage of Web Request Commands and Cmdlets
    description: Detects the use of various web request commands with command-line tools and Windows PowerShell cmdlets via CommandLine.
    platform: sigma
    severity: medium
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to the SIEM environment
      owner: Detection Engineering
      due: 48h
      evidence: Source provides detection logic for widespread TTP.
  hunt_leads:
    - lead: Search for historical execution of Invoke-WebRequest or curl in process logs
      technique_id: T1059.001
      data_needed:
        - CommandLine
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Adversaries commonly use these tools for initial payload staging.
---

Attackers frequently leverage built-in Windows utilities and PowerShell cmdlets to download secondary payloads, fetch malicious configurations, or establish command-and-control (C2) channels. These tools are often preferred because they are natively present in the operating system, allowing attackers to perform network requests while blending in with legitimate administrative activity. Common utilities include `curl`, `wget`, and various PowerShell cmdlets such as `Invoke-WebRequest` and `Start-BitsTransfer`. Monitoring the execution of these commands is essential for detecting the initial stage of payload delivery or subsequent exfiltration attempts. This brief provides a detection capability for these patterns, focusing on command-line arguments that indicate external data retrieval.

## Impact

Successful abuse of these techniques enables attackers to transition from initial access to full payload execution, facilitate lateral movement, or exfiltrate sensitive data. If these activities are not detected, adversaries may maintain persistence and perform data theft undetected for extended periods.

## Recommendation

Deploy the provided Sigma rule to your SIEM to monitor for the use of web request-related command-line arguments. Prioritize alerts from servers and endpoints that do not typically require external connectivity or the use of automated download utilities.
