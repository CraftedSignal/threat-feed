---
title: Firewall Rule Manipulation via COM API
slug: 2024-01-firewall-rule-bof
description: A tool enables threat actors to add, remove, or query Windows Firewall rules via the COM API (INetFwPolicy2), bypassing traditional command-line tools and potentially evading detection.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - firewall
  - defense-evasion
  - lateral-movement
vendors:
  - Microsoft
products:
  - Windows Firewall
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.reddit.com/r/blueteamsec/comments/1s26to0/firewall_rule_bof_add_remove_or_query_windows/
  - https://github.com/atomiczsec/Adrenaline/tree/main/execution/firewall_rule
rules:
  - title: Detect Firewall Rule Changes via COM API
    description: Detects processes interacting with the Windows Firewall COM API (FirewallAPI.dll) to modify firewall rules.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - image_load
      - windows
  - title: Detect Suspicious Process Accessing Firewall COM Objects
    description: Detects processes interacting with the INetFwPolicy2 COM object through registry events.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

A novel technique has emerged allowing for the manipulation of Windows Firewall rules directly through the COM API (INetFwPolicy2). This method bypasses the need for `netsh.exe` or `cmd.exe`, which are commonly monitored by security solutions. The tool, dubbed "Firewall Rule BOF," enables attackers to add, remove, or query firewall rules, facilitating lateral movement and persistence within a compromised network. This is particularly concerning as it offers a stealthier approach to modifying firewall configurations, potentially evading detection mechanisms that rely on monitoring command-line activity. The availability of this tool lowers the barrier to entry for attackers seeking to modify firewall policies for malicious purposes.

## Attack Chain

1.  Initial access is achieved through an undisclosed method (e.g., compromised credentials, software vulnerability).
2.  The attacker executes a Beacon Object File (BOF) designed to interact with the Windows Firewall COM API.
3.  The BOF uses the INetFwPolicy2 interface to enumerate existing firewall rules to understand the current security posture.
4.  The attacker leverages the BOF to add new firewall rules, opening specific ports to facilitate lateral movement.
5.  Alternatively, the BOF can be used to remove existing firewall rules that are blocking malicious activity.
6.  The attacker establishes a connection to the newly opened port, enabling communication with a compromised system.
7.  The attacker pivots to other internal systems, leveraging the modified firewall rules to bypass network segmentation.
8.  The final objective is achieved, such as data exfiltration or deployment of ransomware.

## Impact

Successful exploitation allows attackers to modify Windows Firewall rules without detection, enabling lateral movement and persistence within a compromised network. This can lead to data exfiltration, ransomware deployment, or other malicious activities. The impact is significant as it weakens the network's security posture and enables attackers to operate undetected. The precise number of potential victims is unknown, but any organization using Windows Firewall is potentially vulnerable.

## Recommendation

*   Monitor process creation events for unusual processes interacting with `FirewallAPI.dll` to detect potential usage of the Firewall Rule BOF technique. Deploy the Sigma rule "Detect Firewall Rule Changes via COM API" to identify such activity.
*   Implement endpoint detection and response (EDR) solutions capable of monitoring COM API calls related to firewall management.
*   Review existing firewall rules to identify any anomalies or unauthorized modifications that may have been introduced by this technique.
*   Enable and review Windows Firewall logs for unexpected rule changes; correlate these with process execution events.
