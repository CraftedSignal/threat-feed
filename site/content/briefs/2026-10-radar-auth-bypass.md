---
title: Authorization Bypass in Radar handleLocalTerminal Endpoint
slug: 2026-10-radar-auth-bypass
description: Radar versions prior to 1.12.2 contain a missing authorization vulnerability allowing attackers to execute commands via the /api/local-terminal WebSocket endpoint.
date: "2026-10-14T14:23:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:radar:radar:*:*:*:*:*:*:*:*
tags:
  - cve-2026-82026
  - remote-code-execution
  - authorization-bypass
vendors:
  - Radar
products:
  - Radar (< 1.12.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can connect to the endpoint to execute /bin/bash -l on the Radar host.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Executing the shell with Radar's own kubeconfig and process credentials injected into the shell environment.
    confidence_band: high
cves:
  - id: CVE-2026-82026
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82026
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Radar to 1.12.2 or later
      owner: IT Operations
      due: 24h
      evidence: NVD remediation guidance
  hunt_leads:
    - lead: Web server access logs showing unexpected access to /api/local-terminal
      technique_id: T1059.004
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability exists in handleLocalTerminal WebSocket endpoint at /api/local-terminal
  mitigation_plan:
    - priority: immediate
      action: Upgrade Radar to 1.12.2 or later
      owner: IT Operations
      addresses: CVE-2026-82026
      evidence: NVD guidance
---

Radar versions prior to 1.12.2 contain a critical missing authorization vulnerability within the handleLocalTerminal WebSocket endpoint, located at /api/local-terminal. The application incorrectly relies on a runtime-mode check instead of robust role-based access control (RBAC), allowing authenticated or unauthenticated attackers to interface with the endpoint. This vulnerability enables the execution of /bin/bash -l on the host running the Radar instance. Notably, the vulnerability remains exploitable even when the --disable-local-terminal configuration flag is enabled. An attacker successfully leveraging this flaw gains remote code execution with the privileges of the Radar process, including access to injected kubeconfig and process credentials.

## Impact

Successful exploitation results in full remote code execution on the host running Radar, granting the attacker the same permissions as the application. This potentially exposes Kubernetes cluster credentials and sensitive environment variables stored within the Radar process context, facilitating lateral movement within the cluster or cloud environment.

## Recommendation

* Upgrade all Radar instances to version 1.12.2 or later to remediate CVE-2026-82026.
* Audit web server logs for POST or WebSocket upgrade requests directed at the /api/local-terminal URI from unauthorized source IPs.
* Implement network-level egress filtering for pods or nodes hosting Radar to prevent unauthorized use of the retrieved kubeconfig credentials if exploitation occurs.
