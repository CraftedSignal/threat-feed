---
title: GlassWorm V2 Infrastructure Rotation and GitHub Injection Analysis
slug: 2024-01-26-glassworm-v2-analysis
description: Analysis of GlassWorm V2 reveals infrastructure rotation and GitHub injection techniques.
date: "2026-03-15T13:51:21Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - malware
  - github
  - infrastructure
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573
    technique_name: Encrypted Channel
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://www.reddit.com/r/netsec/comments/1ruekc5/glassworm_v2_analysis_part_2_infrastructure/
  - https://codeberg.org/tip-o-deincognito/glassworm-writeup/src/branch/main/PART2.md
rules:
  - title: Detect Outbound Network Connection to Newly Registered Domain
    description: Detects outbound network connections to newly registered domains, potentially indicating C2 communication.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1573.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Unusual Process Accessing GitHub API
    description: Detects processes that are not commonly associated with GitHub API usage but are making requests to it, potentially indicating malicious code injection or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1573.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This threat brief summarizes an analysis of GlassWorm V2, focusing on its infrastructure rotation and GitHub injection techniques. While specific details regarding the threat actor and initial attack vectors are not provided in this analysis, the report highlights the malware's ability to dynamically change its command and control (C2) infrastructure and potentially leverage GitHub for code injection or storage. Understanding these techniques is crucial for defenders to develop robust detection and mitigation strategies against this evolving threat. The full analysis is available on Codeberg.

## Attack Chain

1.  Initial Access: Specific initial access vector is unknown.
2.  GitHub Injection: The malware leverages GitHub to host malicious code or configurations, potentially obfuscating its activities within legitimate traffic.
3.  Infrastructure Rotation: GlassWorm V2 employs techniques to rotate its C2 infrastructure, making it more difficult to track and block.
4.  Communication: The malware establishes communication with its C2 server using the dynamically updated infrastructure.
5.  Command Execution: The C2 server issues commands to the infected host.
6.  Persistence: Unknown persistence mechanism is used.
7.  Data Exfiltration/Lateral Movement/Impact: The ultimate goal is currently unknown.

## Impact

The impact of a successful GlassWorm V2 infection could range from data theft and system compromise to disruption of services, depending on the specific objectives of the attacker. The use of infrastructure rotation makes it harder to block attacker infrastructure. The GitHub injection may also lead to supply chain concerns.

## Recommendation

*   Monitor network traffic for connections to unusual or newly registered domains, even if they initially appear benign.
*   Implement file integrity monitoring on systems to detect unauthorized modifications to critical system files.
*   Consider using tools that specifically analyze and detect malicious use of GitHub repositories.
