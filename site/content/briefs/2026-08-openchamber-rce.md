---
title: Unauthenticated Remote Code Execution in OpenChamber
slug: 2026-08-openchamber-rce
description: OpenChamber 1.11.7 contains a critical unauthenticated RCE vulnerability in the /api/fs/exec endpoint due to improper command input validation and flawed authentication middleware.
date: "2026-08-06T15:25:36Z"
lastmod: "2026-08-06T17:25:56Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - web-vulnerability
  - cve-2026-53975
vendors:
  - OpenChamber
products:
  - OpenChamber (1.11.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenChamber 1.11.7 contains an unauthenticated remote code execution vulnerability that allows remote attackers to execute arbitrary shell commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The application fails to validate input before passing it to Node.js spawn().
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The path traversal vulnerability in file-serving endpoints allows unauthenticated remote attackers to read arbitrary files.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers can exploit the vacuous isPathWithinRoot guard to read sensitive files such as the JWT signing secret.
    confidence_band: high
cves:
  - id: CVE-2026-53975
    cvss: 9.8
  - id: CVE-2026-53977
    cvss: 7.5
  - id: CVE-2026-53976
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53975
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53976
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53977
rules:
  - title: Detects CVE-2026-53975 Exploitation - Unauthenticated RCE via /api/fs/exec
    description: Detects POST requests to the /api/fs/exec endpoint which is used for command execution in OpenChamber 1.11.7
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
  - title: Detect CVE-2026-53976 Exploitation - Path Traversal in OpenChamber
    description: Detects exploitation attempts against OpenChamber file-serving endpoints using the allowOutsideWorkspace parameter to bypass directory restrictions.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Deploy web server rule to monitor/block /api/fs/exec
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-53975 RCE capability
  mitigation_plan:
    - priority: immediate
      action: Configure UI_PASSWORD for all OpenChamber deployments
      owner: IT Operations
      addresses: CVE-2026-53975
      evidence: Vulnerability analysis indicates authentication is bypassed when this variable is not set
updates:
  - at: "2026-08-06T15:25:46Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-53976 Exploitation - Path Traversal in OpenChamber'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-53976
  - at: "2026-08-06T17:25:56Z"
    level: L2
    summary: added CVE-2026-53976 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-53977
---

OpenChamber version 1.11.7 is susceptible to a critical unauthenticated remote code execution vulnerability (CVE-2026-53975). The vulnerability exists in the /api/fs/exec endpoint, which passes user-provided input directly to the Node.js spawn() function without any validation or sanitization. Furthermore, the application's authentication middleware fails to enforce security when the UI_PASSWORD environment variable is unset. As the default Docker deployment configuration leaves this variable unconfigured, most deployments are exposed to unauthenticated exploitation. An attacker can submit a crafted POST request to trigger arbitrary command execution as the application user, resulting in the server returning the full command output, including stdout, stderr, and the exit code. This poses a significant risk to the integrity and availability of the host environment, particularly in containerized deployments.

## Impact

Successful exploitation allows an unauthenticated remote attacker to execute arbitrary OS commands on the host machine with the privileges of the OpenChamber application user. This could lead to full system compromise, data exfiltration, or deployment of further malicious payloads. The scope of impact is high, as the vulnerability resides in the default configuration for containerized environments.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
* Deploy the provided webserver detection rule to identify malicious POST requests targeting the /api/fs/exec endpoint.
* Audit all OpenChamber deployments to ensure the UI_PASSWORD environment variable is explicitly configured to a strong, unique password.
* Update OpenChamber to the latest patched version once available.
* Implement egress network filtering to prevent the application container from initiating unauthorized external connections.
