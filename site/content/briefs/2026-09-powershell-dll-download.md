---
title: Detection of DLL Downloads via PowerShell Cmdlets
slug: 2026-09-powershell-dll-download
description: This brief covers the detection of suspicious PowerShell activity involving the use of web download cmdlets to retrieve and save DLL files to the local file system.
date: "2026-09-01T12:23:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - powershell
  - c2
  - malware-delivery
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Adversaries frequently leverage living-off-the-land binaries such as PowerShell to facilitate the delivery of payloads.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: ""
    evidence: A common technique observed in various malware distribution campaigns involves the use of PowerShell cmdlets to download remote payloads.
    confidence_band: high
rules:
  - title: Detect Potential DLL File Download via PowerShell
    description: Detects potential DLL files being downloaded using the PowerShell Invoke-WebRequest or Invoke-RestMethod cmdlets
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell command line logging via GPO
      owner: IT Operations
      due: 48h
  hunt_leads:
    - lead: Search for historical process creation events containing 'OutFile' and '.dll' in command lines
      technique_id: T1105
      data_needed:
        - Process creation events (Event ID 4688 or Sysmon ID 1)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source describes this as a common malware distribution technique
  mitigation_plan:
    - priority: medium
      action: Restrict outbound internet access for non-essential servers to prevent unauthorized tool downloads
      owner: Network Security
      addresses: T1105
---

Adversaries frequently leverage living-off-the-land binaries (LotL) such as PowerShell to facilitate the delivery and execution of malicious payloads. A common technique observed in various malware distribution campaigns involves the use of PowerShell cmdlets - specifically Invoke-WebRequest, Invoke-RestMethod, and their respective aliases (IWR, IRM) - to download remote payloads directly from attacker-controlled infrastructure. When these commands are utilized with the 'OutFile' parameter to save a file with a '.dll' extension, it often indicates an attempt to stage a malicious library for side-loading or reflective loading. Monitoring for these specific command-line patterns allows security operations teams to identify potential initial access or secondary stage malware delivery attempts before the payload is executed.

## Attack Chain

1. Initial access is established, potentially via a phishing document or a malicious link.
2. The attacker triggers a PowerShell process (powershell.exe) from the initial infection point.
3. The process executes a download command using Invoke-WebRequest or Invoke-RestMethod.
4. The command specifies a remote URL (HTTP/HTTPS) as the source.
5. The 'OutFile' parameter is used to write the response body to a local file path.
6. The target filename is specified with a .dll extension.
7. The downloaded DLL is staged on the disk for future loading by an application.
8. Final objective is achieved through the subsequent execution of the malicious DLL via techniques like DLL side-loading.

## Impact

Successful exploitation of this technique allows an attacker to download arbitrary code onto a target system. If the downloaded DLL is malicious, it can lead to full system compromise, remote access, or the deployment of secondary malware payloads, enabling long-term persistence and data exfiltration.

## Recommendation

Deploy the provided Sigma rule to identify PowerShell command-line activity that matches the download-to-DLL pattern. Focus investigations on the source URL identified in the logs and the parent process responsible for spawning the PowerShell instance. Enable process-creation auditing with command-line logging to ensure the 'CommandLine' field is captured for analysis.
