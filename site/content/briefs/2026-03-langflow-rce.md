---
title: Critical RCE Vulnerability in Langflow AI Pipelines (CVE-2026-33017)
slug: 2026-03-langflow-rce
description: A critical remote code execution vulnerability, CVE-2026-33017, exists in Langflow AI pipelines prior to version 1.9.0 that allows an unauthenticated remote attacker to execute code with full server process privileges, impacting availability, integrity, and confidentiality.
date: "2026-03-24T12:00:00Z"
lastmod: "2026-07-30T13:37:43Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - langflow
  - rce
  - cve-2026-33017
  - ai-pipeline
vendors:
  - B3log
  - Langflow
  - n8n
  - Citrix
  - Marimo
  - Apache
products:
  - Siyuan
  - Langflow <= 1.8.2
  - Langflow (< 1.3.4)
  - n8n (< 1.121.0)
  - Citrix NetScaler
  - Marimo notebook
  - Apache Tomcat
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Scanning
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerability-langflow-ai-pipelines-patch-immediately
  - https://github.com/langflow-ai/langflow/security/advisories/GHSA-vwmf-pq79-vjvx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33017
  - https://www.sysdig.com/blog/cve-2026-33017-how-attackers-compromised-langflow-ai-pipelines-in-20-hours
  - https://sploitus.com/exploit?id=8A390AA6-FCBA-5C9C-901C-5D94D4A03A15&utm_source=rss&utm_medium=rss
  - https://unit42.paloaltonetworks.com/autonomous-ai-cyber-attack-campaign/
iocs:
  - type: domain
    value: code.newcli.com
ioc_counts:
  domain: 1
rules:
  - title: Langflow Suspicious Process Execution
    description: Detects suspicious processes spawned by the Langflow process, indicative of potential RCE exploitation
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Langflow Reconnaissance Activity
    description: Detects potential scanning or reconnaissance attempts against Langflow instances.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1046
    data_sources:
      - network_connection
      - linux
rules_count: 2
updates:
  - at: "2026-05-12T20:01:57Z"
    level: L2
    summary: poc_available; added CVE-2026-33017 +1
    sources:
      - sploitus
  - at: "2026-07-30T13:37:43Z"
    level: L1
    summary: new IOCs
    sources:
      - unit42
    source_urls:
      - https://unit42.paloaltonetworks.com/autonomous-ai-cyber-attack-campaign/
---

A critical remote code execution vulnerability, CVE-2026-33017, affects Langflow AI pipelines prior to version 1.9.0. Langflow is a tool used for building and deploying AI-powered agents and workflows. The vulnerability resides in the `build_public_tmp` endpoint, which is intended to be unauthenticated for public flows. However, it incorrectly accepts attacker-supplied flow data, leading to remote code execution with full server process privileges. The vulnerability can be exploited by an unauthenticated remote attacker if the Langflow instance has at least one public flow, a common setup for demos and chatbots. Security researchers have reported that this vulnerability is actively exploited and targeted by scanning activity, making immediate patching or mitigation essential.

## Attack Chain

1.  An unauthenticated attacker sends a malicious request to the `/build_public_tmp` endpoint of a vulnerable Langflow instance.
2.  The Langflow server incorrectly processes the attacker-supplied flow data without proper validation.
3.  The server executes attacker-controlled code due to the lack of authentication and input sanitization on the `build_public_tmp` endpoint.
4.  The attacker gains full server process privileges.
5.  The attacker establishes persistence by modifying system files or creating new user accounts.
6.  The attacker accesses sensitive flow data, including API keys, credentials, and confidential information.
7.  The attacker pivots to other internal systems by leveraging the compromised Langflow instance as a jump host.
8.  The attacker exfiltrates sensitive data or deploys malware, such as ransomware, to disrupt operations.

## Impact

Successful exploitation of CVE-2026-33017 allows an unauthenticated attacker to achieve remote code execution with full server process privileges, impacting availability, integrity, and confidentiality. This can lead to complete system compromise, data breaches, and potential financial losses. Given the active exploitation and targeted scanning activity reported by security researchers, organizations using vulnerable Langflow instances are at immediate risk. The vulnerability allows the attacker to access sensitive data, deploy malware, and disrupt critical AI-powered workflows.

## Recommendation

*   Immediately patch Langflow instances to version 1.9.0 or later to remediate CVE-2026-33017, as recommended by the vendor advisory.
*   Implement network segmentation to limit the blast radius of a potential compromise stemming from CVE-2026-33017.
*   Deploy the provided Sigma rule targeting suspicious processes spawned by the Langflow process to detect exploitation attempts.
*   Enable process monitoring and audit logging on Langflow servers to enhance detection capabilities.
*   Monitor network traffic for unusual outbound connections from Langflow servers, which could indicate post-exploitation activity.
*   Review and restrict access to public flows to minimize the attack surface, as exploitation requires at least one public flow.
