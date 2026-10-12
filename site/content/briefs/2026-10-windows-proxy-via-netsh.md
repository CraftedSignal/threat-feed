---
title: Windows Proxy Configuration via Netsh
slug: 2026-10-windows-proxy-via-netsh
description: The Volt Typhoon group utilizes the Windows netsh utility to establish covert network proxies, enabling persistence and traffic redirection through the portproxy interface.
date: "2026-10-12T18:20:03Z"
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
  - living-off-the-land
  - windows
  - volt-typhoon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1090
    technique_name: Proxy
    evidence: The following analytic identifies the use of netsh.exe to configure a connection proxy, which can be leveraged for persistence.
    confidence_band: high
references:
  - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1090.001/T1090.001.yaml#L81
rules:
  - title: Detect Suspicious Netsh Portproxy Configuration
    description: Detects the use of netsh to configure a port proxy, often used for persistence or C2 traffic redirection.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - persistence
    techniques:
      - T1090.001
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
    - action: Deploy Sigma rule to detect netsh portproxy configurations
      owner: Detection Engineering
      due: 24h
      evidence: Source detection logic identified as high-fidelity
  hunt_leads:
    - lead: Search historical logs for netsh.exe executions containing portproxy
      technique_id: T1090.001
      data_needed:
        - Process creation events with command-line arguments
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Technique is a known LotL method for Volt Typhoon
  mitigation_plan:
    - priority: short_term
      action: Review and restrict administrative privileges for netsh configuration
      owner: IT Operations
      addresses: T1090.001
      evidence: Technique requires administrative privileges
---

The Volt Typhoon threat actor group leverages the built-in Windows utility `netsh.exe` to configure network proxies on compromised hosts. By utilizing the `portproxy` and `v4tov4` command-line parameters, attackers can intercept and redirect network traffic to unauthorized destinations. This technique is frequently employed as a mechanism for maintaining persistence and establishing covert Command and Control (C2) channels. The use of native binaries for malicious purposes, often referred to as Living-off-the-Land (LotL), allows the actor to blend in with legitimate system administration activities and evade signature-based detection. Defenders must prioritize the monitoring of `netsh.exe` execution, specifically when it involves arguments related to port forwarding, to identify potential unauthorized network configuration changes.

## Attack Chain

1. Attacker gains initial access to a target Windows system.
2. Attacker executes `netsh.exe` with administrative privileges.
3. Attacker runs `netsh interface portproxy add v4tov4` to define a new proxy listener.
4. The system registers the listener, effectively creating a persistent network redirector.
5. The proxy listener forwards inbound traffic to the specified C2 infrastructure.
6. Attacker maintains covert connectivity while minimizing the footprint of additional malicious binaries.

## Impact

Successful implementation of this technique allows threat actors to maintain persistent, covert access to critical infrastructure. The primary risk involves the manipulation of network communications and the potential for long-term data exfiltration. If left unmonitored, this behavior facilitates unauthorized ingress into enterprise environments and provides a robust C2 channel for the actor to continue their operations undetected.

## Recommendation

* Deploy the Sigma rule below to detect unauthorized `netsh.exe` usage and tune it against known administrative VPN clients.
* Enable comprehensive process creation auditing (Sysmon Event ID 1 or Windows Event ID 4688) to capture command-line arguments.
* Filter and alert on `netsh.exe` invocations containing `portproxy` or `v4tov4` parameters, as this activity is highly abnormal in standard operational environments.
