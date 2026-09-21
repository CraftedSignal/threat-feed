---
title: RoguePlanet Malware Exploiting Wermgr.exe for Defense Evasion
slug: 2026-09-rogueplanet-wermgr-ads
description: The RoguePlanet malware utilizes the Windows Error Reporting process to create hidden Alternate Data Streams in the temporary directory to facilitate malicious code execution.
date: "2026-09-21T19:13:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - malware
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: The following analytic detects the wermgr.exe process creating an alternate stream in the temp directory.
    confidence_band: high
references:
  - https://github.com/MSNightmare/RoguePlanet/tree/main
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_wermgr_alternate_data_stream_in_temp_dir.yml
rules:
  - title: Detect Wermgr.exe Creating Alternate Data Stream
    description: Detects the wermgr.exe process creating an alternate data stream in the Temp directory, a technique associated with RoguePlanet malware.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1564.004
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for wermgr.exe ADS activity
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic provided in brief
  hunt_leads:
    - lead: Search historical Sysmon Event ID 15 logs for wermgr.exe interacting with ADS in Temp folders
      technique_id: T1564.004
      data_needed:
        - Sysmon Event ID 15
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Threat activity is identified via this specific telemetry
---

RoguePlanet is a malware strain that abuses the legitimate Windows Error Reporting process, wermgr.exe, for defense evasion. By creating Alternate Data Streams (ADS) within the Windows system temporary directory, the malware hides its malicious payloads from standard file system visibility. This technique allows the actor to store and subsequently execute malicious code while masquerading under the identity of a system process. This activity, first observed in mid-2026, is significant because wermgr.exe is typically reserved for system diagnostic and error reporting tasks; its involvement in file stream creation in temp folders is highly anomalous and indicates an attempt to subvert endpoint security controls. Defenders should focus on monitoring for file stream creation events originating from this specific process.

## Attack Chain

1. Initial infection occurs, leading to the execution of the RoguePlanet loader.
2. The malware identifies the wermgr.exe process as a vehicle for concealment.
3. RoguePlanet forces or leverages the wermgr.exe process to write a file to the %TEMP% directory.
4. The malware appends an Alternate Data Stream (ADS) to the file, using the syntax wermgr.exe:streamname.
5. Malicious content is written into the hidden stream to avoid detection by standard file scanners.
6. The hidden malicious payload is triggered for execution from the stream.
7. Final objectives such as data exfiltration or secondary payload deployment are achieved.

## Impact

Successful exploitation by RoguePlanet can lead to persistent system compromise, enabling attackers to gain unauthorized access to data, exfiltrate sensitive information, or deploy additional malware modules. Because the activity leverages a trusted system process, it may bypass some traditional signature-based detections.

## Recommendation

Deploy the following Sigma rule to monitor for anomalous ADS creation events involving wermgr.exe. Ensure Sysmon version 6.0.4 or higher is deployed to capture the necessary FileCreateStreamHash events. Investigate any instances where wermgr.exe creates files containing a colon in the path within the Temp directory.
