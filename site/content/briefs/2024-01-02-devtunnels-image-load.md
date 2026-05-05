---
title: Microsoft Devtunnels Image Load Detection
slug: 2024-01-02-devtunnels-image-load
description: This detection identifies potential misuse of Microsoft Devtunnels within Visual Studio by detecting image load events, indicating that an attacker could expose a compromised system or service to the internet for covert communication and data exfiltration.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - devtunnels
  - reverse-proxy
  - command-and-control
  - data-exfiltration
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Visual Studio
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1090
    technique_name: Proxy
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
references:
  - https://blueteamops.medium.com/detecting-dev-tunnels-16f0994dc3e2
rules:
  - title: Detect Devtunnels Image Load
    description: Detects image load events associated with Microsoft Devtunnels usage.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - defense_evasion
    techniques:
      - T1090
    data_sources:
      - image_load
      - windows
  - title: Detect Devtunnels Process Execution
    description: Detects process execution related to Microsoft Devtunnels.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
      - defense_evasion
    techniques:
      - T1090
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Microsoft Devtunnels, a feature within Visual Studio, allows developers to expose their local development environment to the internet through secure, temporary tunnels. While intended for legitimate purposes like testing webhooks and APIs, attackers can abuse this functionality. By exploiting Devtunnels, a malicious actor could expose a compromised system to the internet, establishing a covert communication channel that circumvents traditional network security measures. This unauthorized access enables data exfiltration, command-and-control (C2) communications, and further compromise of the environment while blending the malicious activity with legitimate development traffic. Defenders should monitor for anomalous image loads associated with Devtunnels to identify potential misuse.

## Attack Chain

1.  Attacker compromises a system within the target network.
2.  Attacker installs or leverages an existing Visual Studio installation on the compromised system.
3.  The attacker configures Microsoft Devtunnels to expose the compromised system to the internet. This may involve creating a new tunnel or hijacking an existing one.
4.  A malicious DLL (devtunnel.dll) is loaded from the temp directory (`*\\AppData\\Local\\Temp\\.net\\devtunnel\\*`) to establish the tunnel.
5.  The attacker uses the established Devtunnel to create a reverse proxy to bypass network security measures.
6.  The attacker uses the Devtunnel for command and control, sending commands and receiving responses from the compromised system.
7.  The attacker exfiltrates sensitive data from the compromised system through the Devtunnel.

## Impact

Successful exploitation of Microsoft Devtunnels can lead to significant security breaches. Attackers can establish persistent covert communication channels, exfiltrate sensitive data, and maintain long-term control over compromised systems. This can result in financial losses, reputational damage, and legal liabilities. The use of Devtunnels can bypass existing network security measures, making detection challenging and increasing the dwell time of attackers within the network.

## Recommendation

*   Enable Sysmon EventID 7 to monitor image load events, which is the data source for the provided detection rule.
*   Deploy the Sigma rule `Detect Devtunnels Image Load` to your SIEM and tune the filter `windows_devtunnels_image_loaded_filter` for your environment to reduce false positives from legitimate developer activity.
*   Monitor network traffic for connections associated with Devtunnels to identify potential covert communication channels.
*   Investigate any alerts triggered by the `Detect Devtunnels Image Load` rule, focusing on systems with development tools installed.
