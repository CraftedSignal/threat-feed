---
title: Insecure Default Configuration in Letta Leading to Unauthenticated RCE
slug: 2026-10-letta-insecure-config
description: Letta versions through 0.16.8 ship with a insecure compose.yaml that disables authentication middleware and exposes a PostgreSQL database with default credentials, enabling remote code execution and administrative account takeover.
date: "2026-10-20T02:31:43Z"
lastmod: "2026-10-20T02:32:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:letta:letta:*:*:*:*:*:*:*:*
tags:
  - configuration-error
  - remote-code-execution
  - web-application
  - authentication-bypass
  - cloud
  - webserver
vendors:
  - Letta
products:
  - Letta (<= 0.16.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote attackers can execute arbitrary Python via POST /v1/tools/run, manage /v1/admin users, or run OS commands via COPY PROGRAM.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
    evidence: Remote attackers can execute arbitrary Python via POST /v1/tools/run
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Letta through 0.16.8 contains an authentication bypass vulnerability that allows API callers to impersonate other users by supplying a self-asserted user_id HTTP header.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers can set user_id to another tenant ID to read and modify that user agents, memory and configuration.
    confidence_band: high
cves:
  - id: CVE-2026-77936
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77936
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77937
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Letta to version > 0.16.8 and ensure LETTA_SERVER_SECURE is configured.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-77936 advisory
  mitigation_plan:
    - priority: immediate
      action: Apply network ACLs to block public access to API and PostgreSQL ports.
      owner: IT Operations
      addresses: CVE-2026-77936
      evidence: Vulnerability disclosure regarding default insecure configurations
updates:
  - at: "2026-10-20T02:32:29Z"
    level: L2
    summary: added coverage for Letta (<= 0.16.8)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-77937
---

Letta versions through 0.16.8 are affected by a critical configuration vulnerability stemming from a default docker-compose.yaml file. The provided configuration fails to enable the LETTA_SERVER_SECURE environment variable, which results in the underlying application failing to load its password middleware. Consequently, the entire API surface becomes unauthenticated. Furthermore, the default deployment exposes an internal PostgreSQL database instance that utilizes default credentials. This vulnerability allows remote, unauthenticated attackers to interact with the API, execute arbitrary Python code, manage administrative users, and leverage database features such as COPY PROGRAM to execute arbitrary OS-level commands. Given the ease of exploitation, this poses a severe risk to any environment running a default Letta container deployment.

## Attack Chain

1. Attacker performs network discovery to identify exposed Letta API ports (default 8283) or PostgreSQL instances (default 5432).
2. Attacker probes the /v1/admin or /v1/tools/run endpoints to confirm the lack of authentication.
3. Attacker accesses the API anonymously to gain insights into the application state or user list.
4. Attacker uses default credentials to gain unauthorized access to the exposed PostgreSQL database instance.
5. Attacker leverages database privileges to perform administrative actions, such as creating or modifying Letta platform users.
6. Attacker sends a POST request to /v1/tools/run containing malicious Python code to achieve remote code execution.
7. Attacker optionally uses PostgreSQL COPY PROGRAM functions to escalate to underlying OS command execution.
8. Attacker achieves persistent access or exfiltrates data from the host environment.

## Impact

Successful exploitation allows remote attackers to bypass all authentication controls, leading to total compromise of the Letta instance. Attackers can execute arbitrary code on the application host, gain full administrative control over the platform, and potentially compromise the underlying infrastructure through database-level command execution. This vulnerability is applicable to any enterprise or individual using Letta in a default containerized deployment.

## Recommendation

* Immediately upgrade Letta to a version later than 0.16.8 where the compose.yaml has been remediated.
* Update existing container deployments to explicitly set LETTA_SERVER_SECURE to 'true' in all environment configurations.
* Rotate default credentials for any PostgreSQL database instances managed by Letta deployments.
* Restrict network access to the Letta API and the PostgreSQL service to trusted internal IP addresses only.
* Audit logs for unauthorized access to the /v1/admin and /v1/tools/run endpoints.
