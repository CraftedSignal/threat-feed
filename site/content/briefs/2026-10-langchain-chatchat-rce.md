---
title: Unauthenticated Remote Code Execution in Langchain-Chatchat
slug: 2026-10-langchain-chatchat-rce
description: Langchain-Chatchat versions up to 0.3.1.3 contain a critical vulnerability in the /tools/call endpoint that permits unauthenticated remote code execution via arbitrary tool invocation.
date: "2026-10-20T02:31:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:langchain_chatchat:langchain_chatchat:*:*:*:*:*:*:*:*
vendors:
  - Langchain-Chatchat
products:
  - Langchain-Chatchat (<= 0.3.1.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote attackers can send a single request naming the shell tool to execute arbitrary OS commands as the server user.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Remote attackers can send a single request naming the shell tool to execute arbitrary OS commands.
    confidence_band: high
cves:
  - id: CVE-2026-75128
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75128
rules:
  - title: Detects CVE-2026-75128 Exploitation - Unauthenticated POST to /tools/call
    description: Detects potential exploitation of CVE-2026-75128 by monitoring for unauthenticated POST requests to the vulnerable /tools/call API endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block external access to /tools/call API endpoint
      owner: SOC
      due: 2h
      evidence: CVE-2026-75128 unauthenticated RCE vulnerability
  mitigation_plan:
    - priority: immediate
      action: Upgrade to a patched version beyond 0.3.1.3
      owner: IT Operations
      addresses: CVE-2026-75128
      evidence: NVD security bulletin
---

Langchain-Chatchat versions through 0.3.1.3 contain a critical remote code execution vulnerability (CVE-2026-75128) resulting from improper access control on the application API. The POST /tools/call endpoint allows any remote attacker to invoke registered system tools by name without prior authentication. Because the application includes a shell execution tool among its default registered assets, an attacker can leverage this endpoint to execute arbitrary OS commands. In the standard Docker deployment configuration, this command execution occurs with root privileges, leading to full system compromise. This vulnerability is highly dangerous due to the absence of authentication requirements and the direct path to command execution.

## Attack Chain

1. Attacker identifies a target host running Langchain-Chatchat (<= 0.3.1.3) exposed to the internet.
2. Attacker performs discovery to identify the API structure, locating the /tools/call endpoint.
3. Attacker sends a crafted HTTP POST request to the /tools/call endpoint.
4. The request payload specifies the 'shell' tool as the target for execution.
5. The application processes the request without validating the user session or permissions.
6. The shell tool executes the attacker-supplied command string on the underlying host.
7. The application returns the output of the command to the attacker.
8. Attacker achieves full system control as the application user (typically root).

## Impact

Successful exploitation allows unauthenticated remote attackers to execute arbitrary commands on the host server. Given the application is frequently deployed in containerized environments, this typically grants the attacker full root access to the container or host filesystem, enabling data exfiltration, lateral movement, or complete system takeover.

## Recommendation

* Immediately restrict network access to the Langchain-Chatchat API endpoint, ensuring it is not reachable from untrusted networks or the public internet.
* Monitor web server logs for POST requests directed at /tools/call, especially those containing references to shell-related utilities in the request body.
* Apply the vendor-provided security patch once available; verify versioning for releases exceeding 0.3.1.3.
* Audit all containerized deployments to ensure the application process is running with the least privilege necessary, rather than the default root user.
