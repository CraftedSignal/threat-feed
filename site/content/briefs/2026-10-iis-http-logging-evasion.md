---
title: IIS HTTP Logging Evasion via AppCmd.exe
slug: 2026-10-iis-http-logging-evasion
description: Adversaries leverage the AppCmd.exe utility on Windows IIS servers to disable HTTP logging as a defense evasion technique to mask post-exploitation activity.
date: "2026-10-12T18:04:29Z"
lastmod: "2026-10-12T18:07:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - iis
  - windows
  - persistence
  - webshell
vendors:
  - Microsoft
products:
  - Internet Information Services (IIS)
  - Internet Information Services
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1505.004
    technique_name: 'Server Software Component: IIS Modules'
    evidence: The following analytic detects the use of AppCmd.exe to disable HTTP logging on IIS servers.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Adversaries may use it to install webshells or backdoors, leading to credit card scraping, persistence, and further post-exploitation.
    confidence_band: high
rules:
  - title: Detect IIS HTTP Logging Disabling via AppCmd
    description: Detects the use of AppCmd.exe to disable HTTP logging, a common technique for defense evasion on IIS servers.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1505.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious IIS Module Installation via AppCmd
    description: Detects the use of AppCmd.exe to install a new IIS module, which may indicate the deployment of a malicious web shell or backdoor.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to detect attempts to disable IIS logging.
      owner: Detection Engineering
      due: 48h
      evidence: This activity is significant because disabling HTTP logging can help adversaries hide their tracks.
  hunt_leads:
    - lead: Search for instances of appcmd.exe in command-line logs.
      technique_id: T1505.004
      data_needed:
        - Process creation events
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: The analytic detects the use of AppCmd.exe to disable HTTP logging.
updates:
  - at: "2026-10-12T18:07:58Z"
    level: L1
    summary: 'added detection rule: Detect Suspicious IIS Module Installation via AppCmd'
    sources:
      - splunk-escu
    source_urls:
      - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_iis_components_add_new_module.yml
---

Adversaries targeting Microsoft Internet Information Services (IIS) servers may utilize the legitimate Windows utility AppCmd.exe to disable HTTP logging. By modifying the server configuration to set 'dontlog:true' or otherwise disabling the HTTP logging module, attackers effectively obscure their post-exploitation activities, including web shell interaction or data exfiltration attempts. This activity is a documented technique for maintaining persistence and ensuring long-term, undetected access to compromised web infrastructure. Defenders should be particularly alert to unauthorized modifications of IIS settings, especially when initiated by processes other than standard IIS management tools.

## Attack Chain

1. Attacker achieves initial execution on a Windows host running IIS.
2. Attacker identifies the need to perform reconnaissance or stage data without generating forensic artifacts.
3. Attacker executes 'appcmd.exe' from the command line or a script.
4. Attacker passes specific arguments, such as 'set config' combined with 'httplogging' or 'dontlog:true', to the binary.
5. The IIS configuration store is updated, silencing HTTP logging for the target site or server.
6. Attacker proceeds with malicious operations, such as deploying web shells or exfiltrating data, without logs being generated.
7. Objective: Long-term stealthy persistence and exfiltration.

## Impact

Successful evasion through the disabling of HTTP logging results in a significant visibility gap, preventing security teams from auditing successful attacks, identifying indicators of compromise in web traffic, or performing incident response for IIS-hosted applications.

## Recommendation

- Deploy the Sigma rule below to monitor for process execution of 'appcmd.exe' with parameters related to logging configuration.
- Baseline administrative behavior in the environment to identify legitimate automated IIS maintenance that might trigger these alerts.
- Enable Sysmon (Event ID 1) or Windows Security Log (Event ID 4688) to capture full process command-line arguments.
- Review and restrict access to IIS administration tools to service accounts only.
