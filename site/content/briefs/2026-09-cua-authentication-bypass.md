---
title: Authentication Bypass in Cua computer-server via Environment Variable Misconfiguration
slug: 2026-09-cua-authentication-bypass
description: Cua computer-server versions prior to 0.3.42 contain an authentication bypass vulnerability triggered when the CONTAINER_NAME environment variable is unset, allowing unauthenticated remote command execution on TCP port 8000.
date: "2026-09-05T11:31:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:cua:computer-server:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - remote-code-execution
  - cve-2026-86121
vendors:
  - Cua
products:
  - computer-server (< 0.3.42)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows unauthenticated attackers to execute arbitrary commands by reaching the service on TCP port 8000.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The service exposes a /run_command endpoint which allows attackers to run shell commands.
    confidence_band: high
cves:
  - id: CVE-2026-86121
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86121
rules:
  - title: Detect CVE-2026-86121 Exploitation - Unauthorized Access to /run_command
    description: Detects unauthenticated access attempts to the sensitive /run_command endpoint on Cua computer-server.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Cua computer-server to 0.3.42 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory requires version 0.3.42 for remediation
  hunt_leads:
    - lead: Unauthorized access to /run_command endpoint
      technique_id: T1190
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Documentation identifies /run_command as the primary exploitation vector
  mitigation_plan:
    - priority: immediate
      action: Restrict access to TCP port 8000
      owner: IT Operations
      addresses: CVE-2026-86121
      evidence: The service binds to all interfaces, requiring network-level restrictions
---

Cua computer-server versions before 0.3.42 suffer from a critical authentication bypass vulnerability. When the application environment is deployed without the CONTAINER_NAME environment variable, the service fails to initialize authentication mechanisms and defaults to binding on all network interfaces. This exposure allows unauthenticated remote actors to interact directly with the application's sensitive API endpoints on TCP port 8000. Successful exploitation provides unauthorized access to the run_command endpoint, enabling arbitrary command execution, unrestricted file system read and write operations, and the ability to initiate interactive PTY shell sessions. Given the service's default network-wide exposure and the severity of the impacted operations, this vulnerability poses a severe risk to host integrity and data confidentiality.

## Attack Chain

1. Attacker performs network discovery to identify services listening on TCP port 8000.
2. Attacker probes the discovered target to confirm the presence of the Cua computer-server service.
3. Attacker identifies a misconfigured instance where the CONTAINER_NAME environment variable is missing.
4. Attacker sends an unauthenticated HTTP request to the /run_command endpoint.
5. The application skips authentication due to the missing environment variable check.
6. Attacker executes arbitrary system commands with the privileges of the application process.
7. Attacker initiates an interactive PTY shell or performs file read/write operations for exfiltration or persistence.

## Impact

Successful exploitation allows unauthenticated remote attackers to achieve full system compromise. Impact includes arbitrary command execution with application-level privileges, unauthorized access to system files, and the establishment of interactive shell sessions. This can lead to complete data exfiltration, lateral movement within the network, or the deployment of persistent malware.

## Recommendation

- Upgrade Cua computer-server to version 0.3.42 or later immediately to resolve the authentication initialization defect.
- Audit all running instances of Cua computer-server to verify the presence of the CONTAINER_NAME environment variable.
- Implement network-level segmentation to restrict access to TCP port 8000 to only trusted management subnets until patching is completed.
- Monitor webserver logs for HTTP requests directed to the /run_command endpoint from unauthorized IP addresses.
