---
title: Remote File Download via Desktopimgdownldr Utility
slug: 2024-01-02-desktopimgdownldr
description: The rule detects the use of desktopimgdownldr.exe to download remote files, which is an abuse of a signed utility often used as an alternative to certutil for transferring malicious tools or malware into a compromised environment.
date: "2024-01-02T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - ingress-tool-transfer
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
rules:
  - title: Detect Remote File Download via Desktopimgdownldr Utility
    description: Detects the execution of desktopimgdownldr.exe with the /lockscreenurl argument to download remote files.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
  - title: Detect Remote File Download via Desktopimgdownldr Utility - Alternate Location
    description: Detects the execution of desktopimgdownldr.exe (from alternate location) with the /lockscreenurl argument to download remote files.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `desktopimgdownldr.exe` utility, typically used for configuring lock screen or desktop images, can be abused by adversaries to download arbitrary files from remote locations. This technique is employed as an alternative to tools like `certutil` for transferring malicious payloads into a compromised environment. The abuse occurs when the utility is invoked with the `/lockscreenurl` argument, followed by an HTTP or HTTPS URL, leading to the download of a remote file. This activity often bypasses traditional download restrictions, making it a stealthy method for introducing malware. The Elastic detection rule identifies this specific behavior based on process arguments. The rule focuses on Windows systems and leverages process execution data to detect instances of this abuse, helping defenders to identify and respond to potential command and control activities.

## Attack Chain

1.  Initial Access: The attacker gains initial access through an existing compromise or vulnerability.
2.  Command Execution: The attacker executes `desktopimgdownldr.exe` via command line or script.
3.  Argument Manipulation: The attacker uses the `/lockscreenurl:http*` argument to specify a remote URL.
4.  File Download: `desktopimgdownldr.exe` downloads a file from the specified remote URL.
5.  Payload Delivery: The downloaded file is a malicious payload (e.g., malware, script).
6.  Execution: The attacker executes the downloaded malicious file.
7.  Persistence/Lateral Movement: The attacker uses the executed payload for persistence or lateral movement within the network.
8.  Objective Achieved: The attacker achieves their objective (e.g., data exfiltration, ransomware deployment).

## Impact

Successful exploitation can lead to the introduction of malware or malicious tools into the targeted environment. This can lead to further compromise, data exfiltration, system damage, or deployment of ransomware. The number of victims and targeted sectors depend on the attacker's objectives. The successful download and execution of malicious files can significantly degrade system security and lead to substantial financial and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Detect Remote File Download via Desktopimgdownldr Utility` to your SIEM and tune for your environment.
*   Monitor process execution events for instances of `desktopimgdownldr.exe` with the `/lockscreenurl` argument.
*   Investigate any identified instances of `desktopimgdownldr.exe` being used with a remote URL, focusing on the source and nature of the downloaded file.
*   Enable Sysmon process-creation logging to enhance detection capabilities as outlined in the `logsource` of the detection rule.
