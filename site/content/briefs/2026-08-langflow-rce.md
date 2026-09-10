---
title: Remote Code Execution in IBM Langflow OSS via A2A Endpoint
slug: 2026-08-langflow-rce
description: IBM Langflow OSS versions 1.0.0 through 1.11.1 contain an unauthenticated remote code execution vulnerability in the A2A public endpoint.
date: "2026-08-28T23:34:49Z"
lastmod: "2026-09-10T23:11:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ibm:langflow:*:*:*:*:oss:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - webserver
  - web-application
  - security-scanner-bypass
  - cve-2026-76059
vendors:
  - IBM
products:
  - Langflow OSS (1.0.0 - 1.11.1)
  - Langflow OSS (1.0.0-1.11.2)
  - Langflow OSS (1.0.0-1.11.5)
  - Langflow OSS (1.0.0 through 1.11.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IBM Langflow OSS 1.0.0 through 1.11.1 could allow a remote attacker to execute arbitrary code due to improper enforcement of security restrictions on the A2A public endpoint.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: An authenticated attacker can exploit this to read arbitrary files from the server, including sensitive configuration files and credentials.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Improper enforcement of public-flow security restrictions and insufficient session isolation allow an unauthenticated attacker to bypass security controls, leading to arbitrary code execution
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: the attacker could cause arbitrary operating system commands to execute on the server in-process.
    confidence_band: high
cves:
  - id: CVE-2026-19286
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19286
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19306
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85025
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76059
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all IBM Langflow OSS deployments and assess version status.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-19286 severity 9.8
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest version of Langflow OSS or restrict network access to the A2A endpoint.
      owner: IT Operations
      addresses: CVE-2026-19286
      evidence: Vulnerability requires security restriction enforcement
updates:
  - at: "2026-09-04T17:27:24Z"
    level: L2
    summary: added coverage for Langflow OSS (1.0.0-1.11.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19306
  - at: "2026-09-10T23:09:35Z"
    level: L2
    summary: added coverage for Langflow OSS (1.0.0-1.11.5)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85025
  - at: "2026-09-10T23:11:03Z"
    level: L2
    summary: added coverage for Langflow OSS (1.0.0 through 1.11.5)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76059
---

IBM Langflow OSS versions 1.0.0 through 1.11.1 are susceptible to a critical remote code execution (RCE) vulnerability identified as CVE-2026-19286. The issue arises from the improper enforcement of security restrictions on the A2A public endpoint. This flaw allows unauthenticated remote attackers to bypass authorization controls and execute arbitrary code on the underlying host. Given the nature of Langflow as a workflow automation and LLM orchestration tool, successful exploitation could grant an attacker full control over the application server, potentially allowing for data exfiltration, lateral movement, and the deployment of additional malicious payloads.

## Impact

Successful exploitation of CVE-2026-19286 leads to full server compromise. Given the application's frequent deployment in cloud and containerized environments for AI/ML pipeline management, this vulnerability poses a severe risk to intellectual property and sensitive credentials stored within the workflow environment.

## Recommendation

- Upgrade to a version of Langflow OSS beyond 1.11.1 that addresses CVE-2026-19286.
- Implement strict network access control lists (ACLs) to limit exposure of the A2A endpoint to known, trusted management segments.
- Monitor web application logs for unexpected POST requests directed at the /api/a2a or similar A2A-prefixed endpoints originating from external or unauthorized IP addresses.
