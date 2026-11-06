---
brief_id: brief-2026-03-24-langflow-rce
event_id: brief-2026-03-24-langflow-rce
revision: 3
activity_at: "2026-11-06T15:07:50Z"
revision_history:
  - revision: 2
    at: "2026-11-01T10:58:48Z"
    checksum: sha256:394b70e2dea9f4ed7111b61793a335ee9542051ae2aa11879b5abaab51c19d43
    summary: exploited:true; poc_available; added CVE-2026-33017
    changed_fields:
      - claim_state
      - cpes
      - cves
      - exploitation_evidence
      - has_poc
      - iocs
      - lastmod
      - poc_references
      - references
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TATOSEC-CVE-2026-33017-LANGFLOP&utm_source=rss&utm_medium=rss
  - revision: 3
    at: "2026-11-06T15:07:50Z"
    checksum: sha256:26b7e22dceb2d6f77cd8cd8477906ac0a0c24fd0f26959ca0ed59b11d9c2bd61
    summary: added coverage for Langflow
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - priority
      - priority_signals
      - qa_status
      - references
      - source_assessment
      - tags
      - ttps
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4368
title: Critical RCE Vulnerability in Langflow AI Pipelines (CVE-2026-33017)
slug: 2026-03-langflow-rce
description: A critical remote code execution vulnerability, CVE-2026-33017, exists in Langflow AI pipelines prior to version 1.9.0 that allows an unauthenticated remote attacker to execute code with full server process privileges, impacting availability, integrity, and confidentiality.
date: "2026-03-24T12:00:00Z"
lastmod: "2026-11-06T15:06:54Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TATOSEC-CVE-2026-33017-LANGFLOP&utm_source=rss&utm_medium=rss
  observed_at: "2026-11-01T08:09:12Z"
  confidence: medium
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TATOSEC-CVE-2026-33017-LANGFLOP&utm_source=rss&utm_medium=rss
tags:
  - langflow
  - rce
  - cve-2026-33017
  - ai-pipeline
  - denial-of-service
  - vulnerability
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
  - Langflow
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Ein entfernter, authentisierter Angreifer kann eine Schwachstelle in Langflow ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
cves:
  - id: CVE-2026-33017
    cvss: 9.8
    epss: 0.96177
    kev_status: "false"
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerability-langflow-ai-pipelines-patch-immediately
  - https://github.com/langflow-ai/langflow/security/advisories/GHSA-vwmf-pq79-vjvx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33017
  - https://www.sysdig.com/blog/cve-2026-33017-how-attackers-compromised-langflow-ai-pipelines-in-20-hours
  - https://sploitus.com/exploit?id=8A390AA6-FCBA-5C9C-901C-5D94D4A03A15&utm_source=rss&utm_medium=rss
  - https://unit42.paloaltonetworks.com/autonomous-ai-cyber-attack-campaign/
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TATOSEC-CVE-2026-33017-LANGFLOP&utm_source=rss&utm_medium=rss
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4368
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
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all deployed Langflow instances
      owner: IT Operations
      due: 24h
      evidence: BSI advisory WID-SEC-2026-4368
  hunt_leads:
    - lead: Identify authenticated users conducting anomalous or high-volume request patterns against Langflow API endpoints
      technique_id: T1498
      data_needed:
        - Web server access logs
        - Application-level request logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows authenticated remote DoS
  mitigation_plan:
    - priority: medium
      action: Monitor vendor security advisories and apply patches once available
      owner: IT Operations
      addresses: Langflow DoS vulnerability
      evidence: BSI advisory
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
  - at: "2026-11-01T10:57:59Z"
    level: L3
    summary: exploited:true; poc_available; added CVE-2026-33017
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TATOSEC-CVE-2026-33017-LANGFLOP&utm_source=rss&utm_medium=rss
  - at: "2026-11-06T15:06:54Z"
    level: L1
    summary: added coverage for Langflow
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4368
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
