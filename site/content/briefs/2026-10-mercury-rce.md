---
title: Unauthenticated Remote Code Execution in Mercury via /api/kernels
slug: 2026-10-mercury-rce
description: The Mercury server defaults to unauthenticated access and uses an ineffective blocklist mechanism, enabling remote, unauthenticated attackers to execute arbitrary Python code via the /api/kernels websocket endpoint.
date: "2026-10-19T20:10:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:mljar:mercury:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - web-application-vulnerability
  - jupyter
vendors:
  - MLJAR
products:
  - mercury (<= 3.2.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any unauthenticated network client can POST /api/kernels ... open websocket ... send an execute_request with arbitrary code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: any unauthenticated network client can ... send an execute_request with arbitrary code -> arbitrary Python execution = RCE
    confidence_band: high
cves:
  - id: CVE-2026-111058
    cvss: 9.8
references:
  - https://github.com/advisories/GHSA-rv4m-xm3f-3ccq
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to Mercury instances via firewall or WAF to block unauthorized /api/kernels access.
      owner: IT Operations
      due: 24h
      evidence: Unauthenticated access to /api/kernels allows RCE.
  mitigation_plan:
    - priority: immediate
      action: Configure Mercury to require robust authentication tokens and enable XSRF protection.
      owner: IT Operations
      addresses: CVE-2026-111058
      evidence: Mercury defaults to tokenless access, bypassing security.
---

Mercury, a framework for converting Jupyter notebooks into web applications, is vulnerable to unauthenticated remote code execution due to its default insecure configuration. By default, the application runs without requiring authentication tokens or passwords and disables XSRF checks. While Mercury attempts to restrict access to sensitive endpoints via a hardcoded blocklist, the `/api/kernels` endpoint is omitted to maintain core functionality. A flaw in the `patch_kernel_websocket_handler` function fails to filter or validate incoming WebSocket messages, specifically `execute_request` packets. Consequently, any unauthenticated network attacker can bypass intended security boundaries to provision kernels and execute arbitrary Python commands with the privileges of the Mercury server process. This vulnerability, tracked as CVE-2026-111058, affects all versions up to and including 3.2.5. This issue is distinct from previously patched terminal-based vulnerabilities and highlights a fundamental architectural risk in the reliance on blacklisting for securing Jupyter-based environments.

## Attack Chain

1. Attacker performs reconnaissance to identify a network-exposed Mercury instance running with default (unauthenticated) settings.
2. Attacker sends an HTTP POST request to `/api/kernels` to request a new kernel session.
3. The Mercury server returns a 201 Created response containing a new kernel ID, as the endpoint is not covered by the security blocklist.
4. Attacker initiates a WebSocket connection to the `/api/kernels/<id>/channels` endpoint associated with the created kernel.
5. Attacker transmits an `execute_request` message over the established WebSocket connection containing malicious Python payloads.
6. The `patch_kernel_websocket_handler` intercepts the message to perform idle-timeout tracking but fails to inspect or block the execution request content.
7. The server processes the malicious payload, resulting in arbitrary code execution under the context of the Mercury application service account.
8. Final objective achieved: unauthorized host or container compromise, allowing for data exfiltration or lateral movement.

## Impact

Successful exploitation leads to full remote code execution on the server hosting the Mercury instance. Because the application typically runs with service-level privileges, this allows attackers to access sensitive environment variables, secrets, application data, and potentially pivot to underlying host systems or adjacent cloud infrastructure. All default deployments of Mercury versions 3.2.5 and earlier are considered critically exposed.

## Recommendation

Prioritized actions for security teams:
- Immediately restrict network access to the Mercury service using firewall rules or ingress controllers, allowing only known, authorized IP ranges.
- Patch Mercury instances or migrate to a configuration that mandates robust per-request authentication (tokens or passwords) by default, as the existing blocklist architecture is fundamentally insufficient.
- Review web server access logs for anomalous POST requests to `/api/kernels` from unauthorized external source IPs.
- Monitor for unexpected child processes spawned by the Mercury service user (e.g., shells, network utilities, or scripts) using EDR telemetry.
- Verify that XSRF protections are enabled in the application configuration, as they are disabled by default in tokenless deployments.
