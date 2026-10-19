---
title: CVE-2026-111057 - Unauthenticated Remote Code Execution in Mercury
slug: 2026-10-mercury
description: A configuration error in Mercury framework versions 3.0.0 through 3.2.3 allows unauthenticated attackers to bypass endpoint restrictions and access the Jupyter Server terminal API for remote code execution.
date: "2026-10-19T18:09:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:mercury_project:mercury:*:*:*:*:*:*:*:*
tags:
  - web-application
  - rce
  - python
vendors:
  - Mercury
products:
  - Mercury (3.0.0-3.2.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An unauthenticated attacker can use the resulting interactive operating-system shell to execute commands and access data available to the Mercury process.
    confidence_band: high
cves:
  - id: CVE-2026-111057
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111057
rules:
  - title: Detect CVE-2026-111057 Exploitation - Unauthorized Access to Jupyter Terminals
    description: Detects potential exploitation of CVE-2026-111057 by monitoring for HTTP requests to the Jupyter terminal API, which should be protected in a default Mercury deployment.
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
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Mercury to version 3.2.4 or later
      owner: IT Operations
      due: 24h
      evidence: This issue is fixed in version 3.2.4.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Mercury to 3.2.4
      owner: IT Operations
      addresses: CVE-2026-111057
      evidence: Source notes fix in 3.2.4
---

Mercury is a Python framework designed to transform Jupyter notebooks into web applications and dashboards. A critical security flaw identified in versions 3.0.0 through 3.2.3 stems from a missing comma within the `BLOCKED_PATTERNS` configuration. This syntax error results in the concatenation of `/lab` and `/api/terminals` regular-expression literals, effectively creating an unintended bypass of the security blocklist. Consequently, unauthenticated users can access the underlying Jupyter Server terminal API, which should be restricted. By interacting with this API, an attacker can launch an interactive shell on the host operating system, leading to arbitrary command execution and potential data exfiltration from the system running the Mercury process. This vulnerability is addressed in Mercury version 3.2.4.

## Attack Chain

1. Attacker performs reconnaissance to identify a web application running the Mercury framework.
2. Attacker crafts a malicious HTTP request targeting the `/api/terminals` endpoint.
3. The Mercury web service processes the request, and due to the `BLOCKED_PATTERNS` configuration error, the terminal endpoint check is bypassed.
4. The request is forwarded to the underlying Jupyter Server process.
5. The Jupyter Server grants the unauthenticated request, allowing the initiation of a new terminal session.
6. The attacker interacts with the exposed terminal API to spawn a persistent shell or execute arbitrary commands.
7. Attacker executes post-exploitation commands to exfiltrate data or establish secondary persistence.

## Impact

Successful exploitation of CVE-2026-111057 allows unauthenticated remote code execution with the privileges of the user account running the Mercury process. This represents a critical risk to confidentiality, integrity, and availability for any environment hosting Jupyter-based web applications, potentially resulting in full system compromise.

## Recommendation

* Upgrade all instances of Mercury to version 3.2.4 or later immediately to patch the configuration error documented in CVE-2026-111057.
* Audit access logs for any POST or GET requests to `/api/terminals` originating from unauthorized or external IP addresses.
* Ensure the Mercury service process is running with the principle of least privilege, specifically restricting access to sensitive files and system binaries to limit the impact of a potential RCE.
* Deploy network-level ingress filtering to restrict access to management endpoints of the Mercury/Jupyter environment.
