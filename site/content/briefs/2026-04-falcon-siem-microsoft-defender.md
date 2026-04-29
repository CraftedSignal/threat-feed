---
title: CrowdStrike Falcon SIEM Integration with Microsoft Defender
slug: 2026-04-falcon-siem-microsoft-defender
description: CrowdStrike's Falcon Next-Gen SIEM expands to support third-party EDR solutions, beginning with Microsoft Defender, to unify detection, investigation, and response without requiring the Falcon sensor and modernize security operations.
date: "2026-03-28T22:14:01Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - siem
  - edr
  - integration
  - microsoft-defender
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Detect Suspicious Process Creation via Microsoft Defender Telemetry
    description: Detects suspicious process creations that may indicate post-exploitation activity based on Microsoft Defender Telemetry ingested into CrowdStrike Falcon SIEM.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detecting Data Transformation via Falcon Onum
    description: Detects alterations to telemetry data at the point of ingestion using Falcon Onum.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CrowdStrike is expanding its Falcon Next-Gen SIEM to incorporate third-party EDR solutions, starting with Microsoft Defender. This integration aims to allow organizations to modernize their SOC without replacing existing endpoint agents, addressing the issue of fragmented security systems. Modern attacks exploit gaps across endpoint, identity, network, and cloud environments, forcing security teams to investigate across disparate systems. Falcon Next-Gen SIEM combines index-free search, AI-driven threat detection, and automation across diverse environments to provide a data-agnostic approach to SOC transformation, improving detection and response times. By integrating Microsoft Defender telemetry, Falcon Next-Gen SIEM unifies detection, investigation, and response within a single console.

## Attack Chain

This threat brief focuses on the integration of security tools rather than a specific attack chain.  However, the value of the integration is to defend against a variety of attack chains, a generalized example follows:
1.  Initial Access: An attacker gains initial access through methods such as phishing or exploiting a vulnerability. (T1566, T1190)
2.  Execution: The attacker executes malicious code on the endpoint. (T1059)
3.  Persistence: The attacker establishes persistence to maintain access to the compromised system. (T1547)
4.  Lateral Movement: The attacker moves laterally within the network to access additional systems. (T1021)
5.  Credential Access: The attacker attempts to steal credentials to escalate privileges and access sensitive data. (T1003)
6.  Data Exfiltration: The attacker exfiltrates sensitive data from the compromised systems. (T1041)
7.  Impact: The attacker achieves their objective, such as data theft, system disruption, or ransomware deployment. (T1486)

## Impact

The integration of Microsoft Defender with CrowdStrike Falcon Next-Gen SIEM aims to reduce the impact of successful attacks.  Without unified detection, organizations may experience delayed detection, slower response times, increased operational costs, and potential data breaches. The number of potential victims and sectors targeted is broad, as this integration applies to any organization using both Microsoft Defender and CrowdStrike. Success of an attack despite these tools leads to data breaches, financial losses, and reputational damage.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious processes indicative of post-exploitation activity.
*   Investigate systems generating process creation events flagged by the rules in this brief (process_creation logging).
*   Review Falcon Onum settings to ensure proper filtering and routing of Microsoft Defender telemetry to optimize data fidelity and reduce storage costs (Falcon Onum documentation).
*   Utilize federated search capabilities to investigate across live, network, and archived data sources, including Falcon LogScale, ExtraHop, and Amazon S3 (Falcon Next-Gen SIEM documentation).
