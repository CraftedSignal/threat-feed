---
title: Windows PortProxy Registry Modification for Persistence
slug: 2026-10-windows-portproxy-persistence
description: Threat actors, including Volt Typhoon, modify Windows registry keys to configure PortProxy via netsh, enabling persistent network traffic redirection and potential command-and-control.
date: "2026-10-12T18:20:13Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Volt Typhoon
  - Vanguard Panda
  - Bronze Silhouette
  - Insidious Taurus
tags:
  - persistence
  - command-and-control
  - windows
  - netsh
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1090.001
    technique_name: 'Proxy: Internal Proxy'
    evidence: The following analytic detects the modification of registry keys related to the Windows Proxy settings via netsh.exe.
    confidence_band: high
references:
  - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1090.001/T1090.001.yaml
rules:
  - title: Detect Windows PortProxy Registry Modification
    description: Detects modifications to registry keys under PortProxy which are used to establish persistent network proxies via netsh.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1090.001
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
    - action: Deploy Sigma rule to monitor Registry Event 13 for PortProxy path.
      owner: Detection Engineering
      due: 24h
      evidence: Rule matches observed TTPs in source
  hunt_leads:
    - lead: Search for existing PortProxy configurations across all endpoints.
      technique_id: T1090.001
      data_needed:
        - Endpoint registry state or netsh output
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation identifies this as a persistent threat technique.
  mitigation_plan:
    - priority: short_term
      action: Enforce strict host-based firewall policies and limit administrative access to netsh.
      owner: IT Operations
      addresses: T1090.001
      evidence: Source identifies netsh abuse as primary vector.
---

Attackers, notably those associated with the Volt Typhoon campaign, leverage the built-in Windows netsh utility to modify registry keys associated with the PortProxy feature. By altering keys within the HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp registry path, adversaries establish persistent network proxies. This technique allows attackers to forward traffic through compromised hosts, effectively bypassing network segmentation or security restrictions. By controlling these registry entries, the attacker can ensure that redirected traffic or helper DLLs are executed whenever the netsh service is invoked. Defenders should monitor registry modifications targeting these specific keys as a strong indicator of persistence and potential command-and-control infrastructure setup.

## Attack Chain

1. Attacker gains initial access to a target Windows system through undisclosed methods.
2. Attacker performs internal reconnaissance to identify network configuration and potential proxy targets.
3. Attacker executes netsh.exe to configure port forwarding rules using the 'interface portproxy' command.
4. The netsh utility modifies registry keys under HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp to persist the configuration.
5. The system begins forwarding incoming traffic from the specified listening port to a remote destination controlled by the attacker.
6. Attacker utilizes the established proxy to tunnel Command-and-Control (C2) traffic or move laterally within the victim network.
7. Attacker maintains access by ensuring the registry-based configuration remains active through system reboots.

## Impact

The abuse of the Windows PortProxy feature allows attackers to establish resilient backdoors into protected network environments. By turning compromised endpoints into relay nodes, attackers can mask their lateral movement, exfiltrate sensitive data, and evade perimeter-based network security controls. This technique has been specifically associated with the Volt Typhoon campaign targeting critical infrastructure.

## Recommendation

1. Deploy the provided Sigma rule to monitor registry modifications within the PortProxy service path.
2. Implement registry monitoring (Sysmon Event ID 13) focusing on the HKLM\System\CurrentControlSet\Services\PortProxy registry hive.
3. Audit the current PortProxy configuration across the fleet using netsh interface portproxy show all to identify unauthorized redirection rules.
4. Restrict the ability of non-administrative users to execute netsh and modify system registry keys.
