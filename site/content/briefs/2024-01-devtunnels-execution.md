---
title: Microsoft Devtunnels Execution for Covert Communication
slug: 2024-01-devtunnels-execution
description: The execution of Microsoft devtunnels.exe can be abused by attackers to expose compromised systems to the internet, establish covert communication channels, and bypass network security measures, facilitating data exfiltration or command-and-control.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - devtunnels
  - reverse-proxy
  - command-and-control
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Visual Studio
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
references:
  - https://blueteamops.medium.com/detecting-dev-tunnels-16f0994dc3e2
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_devtunnels_execution.yml
rules:
  - title: Detect Devtunnels.exe Execution
    description: Detects the execution of Microsoft Devtunnels executable, which can be used to expose internal services.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1090
    data_sources:
      - process_creation
      - windows
  - title: Detect Devtunnels DLL Loading
    description: Detects the loading of the devtunnel.dll, which is associated with Microsoft Devtunnels.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1090
    data_sources:
      - image_load
      - windows
rules_count: 2
---

Microsoft Devtunnels, a feature within Visual Studio, enables developers to expose local development environments to the internet via secure tunnels. While designed for legitimate testing and debugging, attackers can abuse this functionality to establish covert communication channels from compromised systems. By executing `devtunnel.exe` or loading `devtunnel.dll`, an attacker can bypass network security measures and blend malicious activity with legitimate development traffic. This allows for remote access, data exfiltration, or command-and-control communications, making detection more challenging. This technique could be used to expose internal services or systems without proper authentication to the outside world, potentially leading to further compromise.

## Attack Chain

1.  Initial compromise of a system via typical methods (e.g., phishing, exploit).
2.  Attacker gains a foothold and establishes persistence on the compromised system.
3.  Attacker executes `devtunnel.exe` or loads `devtunnel.dll`.
4.  The Dev Tunnels feature is configured to expose a service or the entire system to the internet.
5.  A secure, temporary tunnel is established, bypassing normal network security measures.
6.  The attacker uses the tunnel to remotely access the compromised system.
7.  Data exfiltration or command-and-control activities are performed through the tunnel.
8.  The attacker maintains persistent access and control over the compromised system, blending their activities with legitimate development traffic.

## Impact

Successful exploitation allows attackers to create covert communication channels, bypass network security measures, and exfiltrate sensitive data. The use of Dev Tunnels can make it difficult to detect malicious activity, as it blends in with legitimate development traffic. This can lead to prolonged access to compromised systems and significant data breaches. Lateral movement may be easier if internal services are exposed through the tunnel. The number of victims and the extent of the damage depend on the specific targets and the attacker's objectives.

## Recommendation

*   Implement the Sigma rules provided in this brief to detect the execution of `devtunnel.exe` and the loading of `devtunnel.dll` within your environment.
*   Monitor process creation events (Sysmon EventID 1, Windows Event Log Security 4688, CrowdStrike ProcessRollup2) for the execution of `devtunnel.exe`.
*   Investigate any instances of `devtunnel.exe` execution, especially those originating from unusual locations or user accounts.
*   Filter alerts (as mentioned in the known_false_positives) for approved development environments and users to reduce false positives.
*   Enable Sysmon process-creation logging to ensure the effectiveness of the provided Sigma rules.
