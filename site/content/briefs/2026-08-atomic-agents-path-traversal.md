---
title: Path Traversal in atomic-agents-stack Dashboard HTTP Server
slug: 2026-08-atomic-agents-path-traversal
description: The atomic-agents-stack dashboard HTTP server lacks sufficient path validation, enabling unauthenticated attackers to read arbitrary files from the underlying filesystem.
date: "2026-08-13T14:21:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - arbitrary-file-read
products:
  - atomic-agents-stack (1.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: a request can read files outside the intended agents_root
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: a request can read files outside the intended agents_root
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Restrict network exposure of atomic-agents-stack dashboard to loopback interface.
      owner: IT Operations
      due: 24h
      evidence: The default bind is loopback, but --host is an operator-settable documented flag
  mitigation_plan:
    - priority: immediate
      action: Upgrade atomic-agents-stack to patched version.
      owner: IT Operations
      addresses: atomic-agents-stack path traversal
      evidence: 'Fix: route every served path through _io.safe_resolve_under'
---

The atomic-agents-stack dashboard HTTP server, specifically within the `atomic_agents/dashboard/serve.py` module, contains a path traversal vulnerability impacting all versions through 1.0.0. The vulnerability exists because the `DashboardHandler.do_GET` method constructs file paths based on incoming HTTP request URIs without performing containment checks or canonicalizing path segments. By including directory traversal sequences (such as `../`) in a request path, an attacker can bypass the intended `agents_root` directory to access sensitive files on the host filesystem.

While the server defaults to binding to the loopback interface, operators often utilize the `--host` flag to bind to other interfaces, potentially exposing the vulnerability to local area networks. Furthermore, even if bound to loopback, the interface remains susceptible to exploitation via DNS rebinding attacks originating from a victim's browser or server-side request forgery (SSRF) from other services running on the same host. This vulnerability allows for unauthorized file exfiltration and could facilitate further exploitation by exposing application configuration, secrets, or system files.

## Impact

Successful exploitation results in arbitrary file read access on the host system. This could lead to the exposure of sensitive configuration files, environment variables, or other stored data, depending on the permissions of the user account running the atomic-agents-stack process. Organizations deploying this dashboard on non-loopback interfaces or in environments with co-located untrusted services are at a significantly higher risk of compromise.

## Recommendation

* Upgrade atomic-agents-stack to a version where file serving paths are routed through the `_io.safe_resolve_under` function and path traversal sequences are rejected.
* Audit deployment configurations to ensure the HTTP dashboard server is bound only to the loopback interface (127.0.0.1) unless specific, authenticated network access is required.
* Implement network-level access control lists (ACLs) to restrict access to the dashboard's listening port to authorized management IP addresses only.
* Deploy web server or proxy logs monitoring for URI patterns containing directory traversal sequences (e.g., `../`) directed at the dashboard endpoint.
