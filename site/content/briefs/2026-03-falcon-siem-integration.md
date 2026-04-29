---
title: CrowdStrike Falcon Next-Gen SIEM Integrates with Microsoft Defender
slug: 2026-03-falcon-siem-integration
description: CrowdStrike's Falcon Next-Gen SIEM is expanding to support third-party EDR solutions, starting with Microsoft Defender, to enable organizations to modernize their SOC without replacing existing endpoint agents and improve threat detection across diverse environments.
date: "2026-03-23T00:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - siem
  - edr
  - threat-intelligence
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Detect Defender Telemetry Ingestion via Falcon Onum
    description: Detects the ingestion of Microsoft Defender telemetry through Falcon Onum, indicating the integration is active.
    platform: sigma
    severity: informational
    tactics:
      - defensive_evasion
    techniques:
      - T1562
    data_sources:
      - webserver
      - linux
  - title: Falcon SIEM Federated Search Activity
    description: Detects attempts to execute federated searches within Falcon SIEM across multiple data sources.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CrowdStrike is enhancing its Falcon Next-Gen SIEM to incorporate third-party Endpoint Detection and Response (EDR) solutions, initially supporting Microsoft Defender. This integration aims to provide organizations with a unified security operations center (SOC) view without requiring the replacement of existing endpoint agents. By integrating data from multiple sources, including Microsoft Defender, Falcon Next-Gen SIEM seeks to address the challenges posed by fragmented security systems and the increasing complexity of modern attacks. The system combines petabyte-scale search performance with AI-native threat detection and frontline adversary intelligence to accelerate security outcomes across heterogeneous environments. Falcon Onum is embedded within the Falcon platform to deliver real-time data pipelines.

## Attack Chain

This brief focuses on the data integration aspects rather than a specific attack chain. The integration aims to improve visibility across existing attack chains. Therefore, the attack chain steps are generalized to reflect how improved visibility benefits the threat detection lifecycle.

1.  **Initial Access:** An attacker gains initial access through various methods (e.g., phishing, exploitation of vulnerabilities). This is outside the scope of SIEM integration but is a necessary precursor.
2.  **Execution:** The attacker executes malicious code on an endpoint monitored by Microsoft Defender.
3.  **Data Collection:** Microsoft Defender detects suspicious activity and generates telemetry data.
4.  **Data Ingestion:** Falcon Onum ingests, filters, enriches, and routes Microsoft Defender telemetry data into Falcon Next-Gen SIEM via API.
5.  **Correlation & Analysis:** Falcon Next-Gen SIEM correlates the ingested data with other security events and threat intelligence.
6.  **Detection & Alerting:** AI-native threat detection identifies suspicious patterns that might have been missed by siloed tools.
7.  **Investigation & Response:** Security analysts investigate the alerts within the Falcon console, using federated search to access archived data if needed.
8.  **Remediation:** Based on the investigation, security teams take appropriate remediation actions to contain and eliminate the threat.

## Impact

The integration of third-party EDR solutions into Falcon Next-Gen SIEM aims to improve threat detection and response capabilities. A successful integration reduces blind spots, accelerates investigations, and improves the overall effectiveness of the SOC. Failure to properly integrate and manage data from diverse sources could lead to missed threats, delayed response times, and increased risk of successful attacks. The primary benefit is improved security outcomes by leveraging comprehensive data analysis and threat intelligence.

## Recommendation

*   Evaluate the integration of Microsoft Defender data into CrowdStrike Falcon Next-Gen SIEM to improve cross-environment visibility, referencing the blog post for capabilities and benefits.
*   Utilize Falcon Onum for real-time data transformation and filtering to reduce noise and improve data fidelity within the Falcon Next-Gen SIEM, as described in the overview section.
*   Explore Falcon Next-Gen SIEM’s federated search capabilities to investigate across live, network, and archived data sources, without costly re-ingestion or duplication, as mentioned in the overview.
*   Operationalize threat intelligence at scale using the Third-Party Indicator Management features within Falcon Next-Gen SIEM.
