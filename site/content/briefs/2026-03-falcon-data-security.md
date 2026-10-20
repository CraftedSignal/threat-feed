---
brief_id: brief-2026-03-30-falcon-data-security
event_id: brief-2026-03-30-falcon-data-security
revision: 1
activity_at: "2026-03-28T08:12:22Z"
title: CrowdStrike Falcon Data Security Introduction
slug: 2026-03-falcon-data-security
description: CrowdStrike Falcon Data Security is introduced to protect data across evolving environments by discovering, classifying, and defending sensitive data against risks like employee mistakes and credential-based data theft.
date: "2026-03-28T08:12:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
tags:
  - data-security
  - data-loss-prevention
  - cloud-security
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-data-security-secures-data-wherever-it-lives-and-moves/
rules:
  - title: Detect Data Exfiltration via Web Browser
    description: Detects attempts to exfiltrate data through web browsers, potentially indicating unauthorized data movement.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
  - title: Detect Sensitive File Access by Uncommon Processes
    description: Detects processes not typically associated with sensitive data accessing files or directories containing such data.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1005
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CrowdStrike has announced Falcon Data Security, a new solution designed to protect sensitive data across diverse and evolving business environments. This platform aims to provide organizations with the ability to discover and classify sensitive data, monitor its movement in real-time, and prevent data theft. Falcon Data Security addresses a spectrum of threats, including unintentional data leaks caused by employees and malicious data exfiltration by threat actors using compromised credentials. The solution supports a variety of environments, including endpoints, browsers, SaaS applications, cloud services, GenAI tools, and agentic workflows. By providing real-time visibility and control over data movement, Falcon Data Security intends to transform data security from a compliance function into a core component of breach prevention.

## Attack Chain

1.  An employee or adversary gains access to a system or application containing sensitive data (PCI, PII, PHI).
2.  The user attempts to move the sensitive data from an endpoint through a web browser.
3.  Falcon Data Security classifies the data being moved as sensitive.
4.  The system captures context related to the data movement including source, egress channel, user and destination.
5.  Falcon Data Security assesses the risk associated with the data movement.
6.  Based on policy, Falcon Data Security blocks the data movement to prevent exposure.
7.  An alert is triggered within the Falcon platform, providing details about the blocked data movement.

## Impact

The successful deployment of Falcon Data Security aims to reduce the risk of sensitive data exposure resulting from both internal errors and external attacks. By classifying and monitoring data movement, organizations can prevent data breaches, maintain regulatory compliance (e.g., HIPAA, PCI DSS, GDPR), and protect their intellectual property. If implemented correctly, it can minimize the impact of insider threats and credential-based attacks, safeguarding sensitive information across various platforms and environments.

## Recommendation

*   Enable process creation logging to monitor data exfiltration attempts via command-line tools, relevant to Falcon Data Security's real-time data movement assessment.
*   Implement network connection monitoring to detect unauthorized data transfers to external destinations, aligning with Falcon Data Security's ability to see and stop risky data movement.
*   Deploy the provided Sigma rules to identify suspicious processes accessing sensitive data locations to complement Falcon Data Security's classification capabilities.
