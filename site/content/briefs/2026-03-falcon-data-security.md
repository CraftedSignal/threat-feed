---
title: CrowdStrike Falcon Data Security Prevents Data Exfiltration
slug: 2026-03-falcon-data-security
description: CrowdStrike's Falcon Data Security helps organizations understand sensitive data, track its movement, and prevent data theft across endpoints, browsers, SaaS applications, cloud services, GenAI tools, and agentic workflows by leveraging advanced classification and real-time monitoring.
date: "2026-03-28T09:18:29Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - data-exfiltration
  - dlp
  - cloud-security
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-data-security-secures-data-wherever-it-lives-and-moves/
rules:
  - title: Detect Suspicious Data Compression Before Exfiltration
    description: Detects potential data exfiltration attempts by monitoring for the execution of compression tools (e.g., zip, rar, 7z) commonly used to package data before exfiltration.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Data Upload via Web Browser to Cloud Storage Services
    description: Detects potential data exfiltration attempts by monitoring network connections from web browsers to known cloud storage services.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CrowdStrike Falcon Data Security is a new product designed to protect sensitive data across diverse environments. The product aims to address the challenge of securing data as it is created, accessed, transformed, and shared across endpoints, browsers, SaaS applications, cloud services, GenAI tools, and agentic workflows. Falcon Data Security focuses on discovering, classifying, and defending sensitive data against various risks, including employee mistakes and malicious actors using valid credentials to steal data. The solution leverages advanced classification to identify sensitive data and provides real-time visibility into data movement. It offers protection against data theft by enabling security teams to detect and stop data movement that violates policy. Falcon Data Security is delivered through the unified Falcon sensor and managed from a single console.

## Attack Chain

1.  **Initial Access:** An authorized user gains access to a system or application containing sensitive data. This could be through valid credentials or a compromised account.
2.  **Data Discovery:** The attacker identifies sensitive data within the environment, such as PCI, PII, or PHI data. This may involve browsing file shares, databases, or cloud storage.
3.  **Data Access:** The attacker accesses the sensitive data, potentially copying it to a local machine or another location within the network.
4.  **Egress Preparation:** The attacker prepares the data for exfiltration by compressing it into an archive (e.g., ZIP, 7z) and potentially encrypting it to bypass security controls.
5.  **Egress Channel Selection:** The attacker chooses an egress channel for data exfiltration, such as a web browser, removable media, or cloud storage.
6.  **Data Exfiltration:** The attacker exfiltrates the data via the chosen egress channel. This could involve uploading the data to a cloud storage service, transferring it to a USB drive, or sending it via email.
7.  **Covering Tracks:** The attacker attempts to cover their tracks by deleting logs, modifying timestamps, or removing evidence of their activity.

## Impact

Successful data exfiltration can lead to significant financial losses, reputational damage, and legal liabilities. Organizations may face regulatory fines, customer attrition, and loss of competitive advantage. The number of affected individuals and the severity of the impact depend on the type and volume of data stolen. Sectors that handle sensitive data, such as healthcare, finance, and retail, are particularly vulnerable. If the attack succeeds, an organization's sensitive data could be exposed publicly or sold on the dark web.

## Recommendation

*   Deploy Falcon Data Security or a similar data loss prevention (DLP) solution to classify sensitive data and monitor data movement across the environment.
*   Implement multi-factor authentication (MFA) to protect against unauthorized access to systems and applications containing sensitive data.
*   Enable logging on endpoints, cloud services, and SaaS applications to capture data access and movement events. These logs can be used to detect suspicious activity and investigate security incidents.
*   Deploy the Sigma rule "Detect Suspicious Data Compression Before Exfiltration" to identify potential data exfiltration attempts based on process creation events related to compression tools.
*   Monitor network traffic for unusual outbound data transfers, particularly to unfamiliar destinations.
*   Regularly review and update data security policies to ensure they are aligned with current threats and business requirements.
