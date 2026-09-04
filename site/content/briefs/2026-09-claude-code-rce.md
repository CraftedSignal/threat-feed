---
title: Unauthenticated Remote Code Execution in Claude Code Studio
slug: 2026-09-claude-code-rce
description: An unauthenticated OS command injection vulnerability in the Claude Code Studio HTTP server allows remote attackers to execute arbitrary code via drive-by web requests or local network access.
date: "2026-09-04T00:07:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:anthropic:claude_code_templates:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - injection
  - express
  - nodejs
vendors:
  - Anthropic
products:
  - claude-code-templates (<= 1.29.2)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any unauthenticated attacker who can reach the port can execute arbitrary OS commands on the developer's machine.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: 'Because shell: true makes Node join the argv array into a single sh -c string, the fields are parsed by the shell and metacharacters execute.'
    confidence_band: high
cves:
  - id: CVE-2026-73222
    cvss: 8.8
    epss: 0.00202
references:
  - https://github.com/advisories/GHSA-79wm-x847-7cvg
rules:
  - title: Detect CVE-2026-73222 Exploitation - Suspicious POST to Studio API
    description: Detects exploitation attempts against the Claude Code Studio API by looking for shell metacharacters in POST bodies to the studio server.
    platform: sigma
    severity: high
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
    - Detection Engineering
  immediate_actions:
    - action: Block external or LAN-based access to TCP port 3444 on all developer workstations
      owner: SOC
      due: 4h
      evidence: Server binds to 0.0.0.0 and requires no authentication
  mitigation_plan:
    - priority: immediate
      action: Upgrade claude-code-templates to 1.29.4 or later
      owner: IT Operations
      addresses: CVE-2026-73222
      evidence: 'Vulnerable: <= 1.29.2'
---

Claude Code Studio, an HTTP server provided by the `claude-code-templates` npm package (v1.29.2 and earlier), contains a critical OS command injection vulnerability (CVE-2026-73222). When invoked via `npx claude-code-templates --studio`, the application binds an Express server to all network interfaces (0.0.0.0) on port 3444 without authentication. The server explicitly allows cross-origin requests by setting `Access-Control-Allow-Origin: *`.

Two API endpoints, `/api/execute` and `/api/install-agent`, pass user-controlled input fields directly into `child_process.spawn` with the `{ shell: true }` option. This configuration instructs Node.js to invoke the shell to interpret the command string, causing shell metacharacters provided in input fields to execute as system commands. Any unauthenticated attacker with network reachability to the developer's machine, or a malicious website capable of performing a cross-origin POST request, can achieve remote code execution with the developer's privileges.

## Attack Chain

1. The developer executes `npx claude-code-templates --studio` on their local machine, starting an insecure HTTP server on port 3444.
2. The server binds to `0.0.0.0`, making it accessible to any device on the local network (LAN) and susceptible to cross-origin web requests.
3. An attacker triggers an HTTP POST request to the `/api/execute` or `/api/install-agent` endpoint.
4. The request payload includes malicious command injection syntax (e.g., `; touch /tmp/pwned`) within the `prompt` or `agentName` fields.
5. The Express server receives the payload and passes the unvalidated input strings into `child_process.spawn`.
6. Because `shell: true` is enabled, the Node.js runtime executes the input through the system shell (e.g., `sh -c`).
7. The system shell interprets the injected metacharacters, executing the attacker's arbitrary command.
8. The attacker achieves full code execution on the developer's host, gaining access to local files, SSH keys, and environment secrets.

## Impact

The vulnerability results in total compromise of the developer's local account. Successful exploitation grants an attacker the ability to exfiltrate source code, SSH keys, cloud credentials, and sensitive environment variables. This affects all developers utilizing the `--studio` mode of the Claude Code Templates tool globally.

## Recommendation

Prioritized actions for detection and mitigation:
- Upgrade `claude-code-templates` to a version strictly newer than 1.29.2 as soon as a patch is available.
- Until patched, avoid using the `--studio` flag or ensure the local machine is not reachable by untrusted networks.
- Deploy the provided detection rule to monitor for suspicious POST requests to local ports 3444 or related studio services.
- Restrict network access to the port 3444 by implementing host-based firewall rules to permit only localhost traffic.
