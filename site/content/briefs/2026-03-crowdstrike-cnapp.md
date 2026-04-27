---
title: CrowdStrike Falcon Cloud Security CNAPP with Adversary-Informed Risk Prioritization
slug: 2026-03-crowdstrike-cnapp
description: CrowdStrike's new CNAPP capabilities in Falcon Cloud Security focus on adversary-informed risk prioritization by correlating application-layer visibility with threat actor profiles and techniques, enabling security teams to understand cloud risk, prioritize remediation, and accelerate response.
date: "2026-03-28T08:17:27Z"
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA, SCATTERED SPIDER
tags:
  - cloud-security
  - cnapp
  - threat-intelligence
  - risk-prioritization
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1530
    technique_name: Exploitation of Cloud-Based Applications
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1589
    technique_name: Gather Victim Identity Information
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Overly Permissive Cloud Storage Access
    description: Detects overly permissive access to cloud storage resources, which can be exploited by attackers for reconnaissance and data access.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Cloud Instance Metadata API Access
    description: Detects suspicious access to the cloud instance metadata API, which could indicate reconnaissance or credential theft attempts.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1589.002
    data_sources:
      - network_connection
      - aws
  - title: Detect Unapproved LLM Usage
    description: Detects network connections to external Large Language Models (LLMs) from applications, which could indicate shadow AI activity or sensitive data exposure.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 3
---

CrowdStrike has enhanced its Falcon Cloud Security with new Cloud-Native Application Protection Platform (CNAPP) capabilities designed to prioritize cloud risks based on adversary behavior. This update addresses critical gaps in current CNAPP solutions, including limited visibility into business applications, a lack of integration of adversary intelligence, and difficulties in tracing the root cause of exposures. The new features provide application-layer visibility, correlate risks with threat…
