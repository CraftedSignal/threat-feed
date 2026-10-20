---
title: Remote Code Execution in Aix-DB ChatBI Agent
slug: 2026-10-aix-db-rce
description: Authenticated non-admin users can execute arbitrary system commands in Aix-DB version 1.2.4 by exploiting an unvalidated execute tool within the ChatBI agent via crafted HTTP requests.
date: "2026-10-20T02:32:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:aix-db:aix-db:1.2.4:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - web-application
  - cve
vendors:
  - Aix-DB
products:
  - Aix-DB (1.2.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can send crafted chat input to POST /dify/get_answer or upload documents with malicious text to run host commands
    confidence_band: high
cves:
  - id: CVE-2026-77926
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77926
rules:
  - title: Detects CVE-2026-77926 Exploitation - RCE via ChatBI deepagents
    description: Detects suspicious command execution patterns stemming from the ChatBI deepagents execute tool, targeting the /dify/get_answer endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block or monitor access to /dify/get_answer from untrusted subnets
      owner: SOC
      due: 24h
      evidence: Vulnerability allows authenticated non-admin users to execute commands
  enrichment_needed:
    - item: Aix-DB security update
      owner: CTI
      reason: Need to track fixed version release
      evidence: Software current version is 1.2.4
  mitigation_plan:
    - priority: immediate
      action: Upgrade Aix-DB once patch is available
      owner: IT Operations
      addresses: CVE-2026-77926
      evidence: NVD source confirms vulnerability in 1.2.4
---

Aix-DB version 1.2.4 contains a critical remote code execution (RCE) vulnerability identified as CVE-2026-77926. The vulnerability exists within the ChatBI common agent, specifically due to an ungated tool known as 'deepagents execute'. This flaw allows authenticated non-admin users to manipulate the agent's input, resulting in the execution of arbitrary operating system commands on the underlying host. The impact of this vulnerability is significant, as successful exploitation provides attackers with the ability to exfiltrate sensitive data, including datasource credentials and model API keys, potentially leading to full system compromise.

## Impact

Successful exploitation of CVE-2026-77926 allows attackers to bypass intended access controls, executing OS-level commands with the privileges of the Aix-DB application. This facilitates the theft of stored credentials, API keys, and internal system configurations, posing a high risk to organizations utilizing this software.

## Recommendation

1. Immediately restrict access to the '/dify/get_answer' endpoint at the web application firewall (WAF) or load balancer level for unauthorized users.
2. Audit application logs for abnormal command patterns originating from the ChatBI agent.
3. Patch Aix-DB to the latest version once a security update is released by the vendor.
4. Perform a credential rotation for all datasource secrets and model API keys if unauthorized access is suspected.
