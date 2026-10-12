---
title: Windows Registry Modification to Enable Proxy Settings
slug: 2026-10-windows-proxyenable-modification
description: Adversaries and malware, including DarkGate, modify the Windows registry key 'ProxyEnable' to redirect network traffic through a proxy for C2 communication and data exfiltration.
date: "2026-10-12T18:13:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - malware
  - windows
  - registry
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The following analytic detects modifications to the Windows registry key ProxyEnable to enable proxy settings.
    confidence_band: high
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.darkgate
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1112/T1112.yaml#L1034
rules:
  - title: Detect Windows Registry ProxyEnable Modification
    description: Detects modifications to the 'ProxyEnable' registry key, which is often performed by malware to redirect network traffic.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for ProxyEnable registry modification
      owner: Detection Engineering
      due: 48h
      evidence: Source explicitly identifies ProxyEnable as a malicious registry target.
  hunt_leads:
    - lead: Identify processes modifying proxy-related registry keys
      technique_id: T1112
      data_needed:
        - Sysmon Event ID 13
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Malware families like DarkGate utilize this registry manipulation.
  mitigation_plan:
    - priority: medium
      action: Implement GPO to restrict registry modifications to critical keys
      owner: IT Operations
      addresses: T1112
      evidence: Registry tampering is a standard technique for defense evasion.
---

Adversaries and malware families, most notably the DarkGate loader, modify specific Windows registry keys to manipulate system network behavior. By setting the 'ProxyEnable' value within 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' to '1', attackers force host traffic through an attacker-controlled proxy server. This technique allows adversaries to bypass localized network security controls, establish stealthy Command and Control (C2) communication, and facilitate the exfiltration of sensitive data. Because this modification affects the system's global internet settings, it provides a persistent method for traffic interception and manipulation until manually reverted or remediated by security teams.

## Impact

Successful exploitation of this technique permits an attacker to route all outbound traffic through an external, malicious proxy. This facilitates the masquerading of C2 traffic as legitimate web traffic, evades detection by some network-based intrusion prevention systems, and allows for the seamless exfiltration of data from the compromised host. The persistence of this configuration ensures that subsequent system activity remains under the influence of the attacker's infrastructure.

## Recommendation

Detection engineering teams should monitor registry modification events for changes to the 'ProxyEnable' key. 

- Deploy the provided Sigma rule to detect unauthorized modifications to the 'ProxyEnable' registry key.
- Enable Sysmon Event ID 13 logging to capture registry set operations.
- Investigate the process responsible for the 'ProxyEnable' modification to identify the underlying malware or malicious actor.
- Audit existing group policies to ensure that proxy configurations are enforced and consistent across the enterprise.
