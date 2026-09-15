---
title: Remote Code Execution in Polyaxon via Unsandboxed Jinja2 Injection
slug: 2026-09-polyaxon-rce
description: Authenticated users can execute arbitrary commands on the Polyaxon scheduler process by injecting malicious Jinja2 payloads into operation specification fields.
date: "2026-09-15T11:40:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:polyaxon:polyaxon:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - jinja2
  - template-injection
  - polyaxon
vendors:
  - Polyaxon
products:
  - Polyaxon (<= 2.16.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can submit runs with Jinja2 payloads in queue, namespace, conditions, presets, or dependencies fields to execute operating system commands in the scheduler process context.
    confidence_band: high
cves:
  - id: CVE-2026-91925
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91925
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Polyaxon to versions beyond 2.16.4.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-91925 remediation requirement.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Polyaxon software to a patched version.
      owner: IT Operations
      addresses: CVE-2026-91925
      evidence: NVD advisory for CVE-2026-91925.
---

Polyaxon versions up to and including 2.16.4 contain a critical vulnerability (CVE-2026-91925) involving the use of an unsandboxed Jinja2 template rendering environment. During server-side run preparation, the application processes several operation specification fields, including queues, namespace, conditions, presets, and dependencies. Because these fields are processed without adequate sandboxing, an authenticated user can inject arbitrary Jinja2 syntax to achieve remote code execution (RCE) in the context of the Polyaxon scheduler process. Successful exploitation allows an attacker to bypass security controls, gain access to underlying infrastructure, and exfiltrate highly sensitive data, including database credentials and internal service tokens used for system authentication. Defenders should prioritize patching and monitor for anomalous process activity originating from the Polyaxon scheduler.

## Attack Chain

1. An authenticated attacker authenticates to the Polyaxon web interface or API.
2. The attacker constructs a malicious operation specification payload containing Jinja2 template injection syntax.
3. The attacker submits a new run or modifies an existing run configuration, populating fields such as 'queues', 'namespace', 'conditions', 'presets', or 'dependencies' with the malicious payload.
4. The Polyaxon scheduler process receives the run preparation request.
5. The server-side rendering engine evaluates the Jinja2 template within the attacker-supplied fields.
6. The underlying OS command is executed by the scheduler process.
7. The attacker leverages the command execution context to query environment variables, read configuration files, or steal service tokens.
8. Final impact is achieved through exfiltration of sensitive credentials or lateral movement within the environment.

## Impact

Successful exploitation of this vulnerability leads to full remote code execution on the server hosting the Polyaxon scheduler. Given the access level required for the scheduler, this enables an attacker to retrieve database credentials, service tokens, and potentially interact with the broader Kubernetes or cloud environment where Polyaxon is deployed. This threat affects all users of Polyaxon versions 2.16.4 and earlier.

## Recommendation

* Upgrade all instances of Polyaxon to a version released after 2.16.4 that includes sandboxed Jinja2 template rendering.
* Implement strict input validation and access control policies for users permitted to define or modify operation specifications.
* Audit access logs for the Polyaxon API to identify users frequently submitting complex operation specifications containing template-related characters.
