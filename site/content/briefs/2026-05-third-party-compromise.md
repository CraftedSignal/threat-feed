---
title: Third-Party Compromise Leading to Stealthy Intrusions via Trusted IT Management Tools
slug: 2026-05-third-party-compromise
description: A threat actor compromised a third-party IT services provider and abused legitimate IT management tools like HPE Operations Agent to conduct a stealthy campaign focusing on long-term access, credential theft, and persistent footholds within a target environment.
date: "2026-05-12T16:06:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - third-party-compromise
  - trusted-relationship
  - lateral-movement
  - credential-access
vendors:
  - Microsoft
  - HPE
products:
  - Microsoft Defender
  - HPE Operations Agent
  - HPE Operations Manager
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://www.microsoft.com/en-us/security/blog/2026/05/12/undermining-the-trust-boundary-investigating-a-stealthy-intrusion-through-third-party-compromise/
rules:
  - title: Detect Suspicious HPE Operations Agent Activity
    description: Detects suspicious activity originating from HPE Operations Agent (OA) processes, which may indicate malicious script execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
  - title: Detect Web Shell Errors.aspx
    description: Detects the presence of Errors.aspx web shell on web servers
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    data_sources:
      - file_event
      - windows
rules_count: 2
---

In May 2026, Microsoft Incident Response investigated an intrusion where the attacker leveraged a compromised third-party IT services provider to gain access to a target environment. The attack avoided noisy exploits and custom malware, instead focusing on the abuse of legitimate and trusted administrative mechanisms, such as the HPE Operations Agent (OA). By operating through established trust relationships and authentication processes, the attacker was able to blend their malicious activity seamlessly into routine operations. This approach enabled the threat actor to establish a durable access, steal credentials, and establish a persistent foothold within the environment without triggering immediate alerts. The investigation highlighted the risks associated with implicit trust paths in third-party management relationships and the potential for attackers to abuse these relationships to move laterally within an environment using legitimate access and tooling.

## Attack Chain

1.  **Initial Access via Third-Party Compromise:** The attacker compromised a third-party IT services provider responsible for managing the target's infrastructure.
2.  **Leveraging HPE Operations Agent (OA):** The attacker abused the HPE OA, a legitimate IT management tool, to execute scripts and binaries on managed hosts.
3.  **Script Execution:** The attacker used the HPE OA framework to execute VBScripts on multiple servers, including web servers and domain controllers.
4.  **Web Shell Deployment:** A web shell named `Errors.aspx` was deployed on internet-exposed web servers (WEB-01 and WEB-02), although the initial deployment mechanism remains undetermined.
5.  **Credential Interception:** The attacker introduced credential interception capabilities on domain infrastructure to harvest and reuse credentials.
6.  **Lateral Movement:** The attacker leveraged harvested credentials and covert connectivity to move laterally across devices, including sensitive assets.
7.  **Persistence:** The attacker established persistent access on internet-facing servers, enabling repeated access.
8.  **Re-establishing Persistence:** After initial detection, the attacker returned to previously established access points to re-enable persistence and deploy additional tooling.

## Impact

The successful intrusion allowed the threat actor to maintain a long-term presence within the target environment, conduct credential theft, and move laterally to access sensitive assets. The abuse of trusted relationships and legitimate tools made the attack difficult to detect, allowing the attacker to operate undetected for an extended period. This highlights the potential for significant damage resulting from third-party compromise and the need for robust monitoring and security measures to detect and prevent such attacks.

## Recommendation

*   Monitor process creation events for unusual executions originating from the HPE Operations Agent (OA) using the "Detect Suspicious HPE Operations Agent Activity" Sigma rule.
*   Inspect web server logs for the presence of web shells, such as `Errors.aspx`, on internet-exposed servers based on file creation events.
*   Review and audit third-party access and trust relationships to minimize the attack surface and identify potential points of compromise.
*   Implement multi-factor authentication (MFA) and least privilege principles to limit the impact of credential theft.
