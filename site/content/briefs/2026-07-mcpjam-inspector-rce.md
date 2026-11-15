---
brief_id: brief-2026-07-mcpjam-inspector-rce
event_id: brief-2026-07-mcpjam-inspector-rce
revision: 1
activity_at: "2026-07-07T14:47:44Z"
title: 'MCPJam Inspector: Remote Code Execution (CVE-2026-23744)'
slug: 2026-07-mcpjam-inspector-rce
description: A publicly available exploit has been released for CVE-2026-23744, a critical remote code execution vulnerability in MCPJam Inspector affecting versions 1.4.2 and earlier.
date: "2026-07-07T14:47:44Z"
lastmod: "2026-11-15T16:06:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Detection logic focuses on standard API management paths associated with the reported vulnerability vector.
cpes:
  - cpe:2.3:a:mcpjam:inspector:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SONNELON-CVE-2026-23744-POC&utm_source=rss&utm_medium=rss
tags:
  - rce
  - exploit
  - web-vulnerability
  - cve
vendors:
  - Mcpjam
products:
  - Inspector <= 1.4.2
  - MCPJam Inspector
product_versions:
  - product: MCPJam Inspector
    range: <= 1.4.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A public exploit has been published on Sploitus demonstrating Missing Authentication for Critical Function in Mcpjam Inspector CVE-2026-23744
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This tool demonstrates the security flaw in versions <=1.4.2 and helps security researchers verify patches. For authorized testing and educational purposes only. Includes multiple payload options, command execution, and session management.
    confidence_band: high
cves:
  - id: CVE-2026-23744
    cvss: 9.8
    epss: 0.43671
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=67E7B26C-E88D-57CD-98B5-8C7095D17279
  - CVE-2026-23744
  - https://cveawg.mitre.org/api/cve/CVE-2026-23744
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SONNELON-CVE-2026-23744-POC
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SONNELON-CVE-2026-23744-POC&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=67E7B26C-E88D-57CD-98B5-8C7095D17279
ioc_counts:
  url: 1
rules:
  - title: Detect MCPJam Inspector Remote Code Execution Attempt
    description: Detects incoming HTTP requests to the MCPJam Inspector interface that may indicate an attempt to install a malicious MCP server, which is the vector for CVE-2026-23744 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch MCPJam Inspector to version 1.4.3 or later.
      owner: IT Operations
      due: 24h
      evidence: Primary CVE evidence identifies version 1.4.3 as the fix.
    - action: Identify all hosts running MCPJam Inspector currently listening on 0.0.0.0.
      owner: SOC
      due: 24h
      evidence: Description states default configuration exposes service to network.
  mitigation_plan:
    - priority: immediate
      action: Bind MCPJam Inspector to 127.0.0.1 or block external access via firewall.
      owner: IT Operations
      addresses: CVE-2026-23744
      evidence: Description specifies the service listens on 0.0.0.0 as a critical configuration weakness.
updates:
  - at: "2026-11-15T16:06:20Z"
    level: L2
    summary: 'added detection rule: Detect MCPJam Inspector Remote Code Execution Attempt'
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SONNELON-CVE-2026-23744-POC&utm_source=rss&utm_medium=rss
---

## Overview
MCPJam Inspector, a development platform for Model Context Protocol (MCP) servers, is vulnerable to remote code execution (CVE-2026-23744). The vulnerability exists because the application defaults to listening on all interfaces (0.0.0.0) instead of local-only (127.0.0.1), allowing unauthenticated remote attackers to trigger the installation of an arbitrary MCP server via a crafted HTTP request. Public proof-of-concept exploit code is available for this vulnerability.

## Impact
Successful exploitation results in arbitrary code execution with the privileges of the MCPJam Inspector process, likely leading to full host compromise. The vulnerability is rated with a CVSS 3.1 base score of 9.8 (Critical).

## Recommendation
- Upgrade MCPJam Inspector to version 1.4.3 or later immediately.
- Until patching is complete, restrict access to the MCPJam Inspector network port using host-based firewalls or network access control lists to ensure it is only accessible from trusted internal management IP addresses.
