---
title: Detection of Malicious File Downloads via Telegram
slug: 2026-10-telegram-download-threat
description: Adversaries leverage the Telegram desktop application on Windows to download malicious payloads and secondary tools by monitoring for associated file stream creation events.
date: "2026-10-19T02:51:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - windows
  - malware-delivery
  - detection
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The following analytic detects suspicious file downloads by the Telegram application on a Windows system.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/download_files_using_telegram.yml
  - https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/
rules:
  - title: Detect Malicious File Downloads via Telegram
    description: Detects file downloads initiated by Telegram.exe by monitoring for the creation of files with a Zone.Identifier stream using Sysmon.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for Telegram-initiated downloads.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic guidance for Sysmon EventID 15.
  hunt_leads:
    - lead: Search historical logs for Sysmon Event ID 15 where Image ends with telegram.exe.
      technique_id: T1105
      data_needed:
        - Sysmon Event ID 15 logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Analytic suggests monitoring this specific event for malicious tool delivery.
  mitigation_plan:
    - priority: medium
      action: Implement application control policies to restrict unauthorized file execution if Telegram is identified as an attack vector.
      owner: IT Operations
      addresses: T1105
      evidence: Behavior is associated with the delivery of secondary stage malware.
---

Security teams should monitor for suspicious file downloads initiated by the Telegram desktop application on Windows systems. Adversaries frequently utilize legitimate messaging applications like Telegram as a delivery mechanism for malicious tools, including network scanners, credential stealers, and cryptocurrency miners. This activity is often a precursor to broader compromise, enabling lateral movement and data exfiltration. The threat is identified by monitoring for the creation of files with a Zone.Identifier stream, which signifies that a file has been downloaded from an external source. This detection technique is highly relevant for identifying the initial stage of payload delivery for various malware families, including Phemedrone Stealer, Snake Keylogger, and XMRig miners, across enterprise environments.

## Attack Chain

1. The adversary distributes a malicious payload or reconnaissance tool through a Telegram channel or direct message.
2. A compromised or targeted user interacts with the message, triggering a download via the Telegram desktop application.
3. The Telegram process (telegram.exe) writes the downloaded file to the local disk.
4. The Windows OS attaches a Zone.Identifier stream (the 'Mark of the Web') to the newly created file, indicating an origin in the Internet zone.
5. The adversary executes the downloaded file or uses it to perform internal network reconnaissance.
6. The attacker leverages the downloaded tools for lateral movement or further exploitation of the host.
7. The final objective, such as data exfiltration or crypto-jacking, is carried out using the weaponized environment.

## Impact

The use of legitimate messaging applications for malware delivery can bypass traditional perimeter-based network security controls. Successful exploitation allows adversaries to establish a foothold, map internal networks, steal sensitive credentials, or deploy resource-intensive payloads like miners. This behavior has been observed in various campaigns, impacting organizations by facilitating unauthorized access and potential data compromise.

## Recommendation

Detection engineering teams should implement monitoring for suspicious file creation events associated with the Telegram application.
- Deploy the provided Sigma rule to identify unauthorized file downloads originating from telegram.exe via Sysmon Event ID 15.
- Use the detected events to investigate the origin of the downloaded file and the subsequent behavior of the process that created it.
- Tune the detection logic to account for legitimate usage of the Telegram application in environments where it is an authorized communication tool.
