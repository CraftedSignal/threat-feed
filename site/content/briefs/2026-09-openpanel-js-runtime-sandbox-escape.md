---
title: Sandbox Escape in OpenPanel js-runtime via Webhook Template Validator
slug: 2026-09-openpanel-js-runtime-sandbox-escape
description: A sandbox escape vulnerability in the OpenPanel js-runtime allows authenticated users with project write access to achieve arbitrary code execution via the webhook template validator.
date: "2026-09-19T14:12:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:openpanel:js-runtime:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - sandbox-escape
  - arbitrary-code-execution
vendors:
  - OpenPanel
products:
  - js-runtime (<= bad75bdd)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: An attacker with project write access can exploit this by utilizing computed property notation to reach the Function constructor, enabling arbitrary code execution within the worker process.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: CVE-2026-93985 identifies a sandbox escape vulnerability in the OpenPanel js-runtime... enabling arbitrary code execution within the worker process.
    confidence_band: high
cves:
  - id: CVE-2026-93985
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93985
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review and restrict webhook template creation permissions to trusted users.
      owner: IT Operations
      due: 24h
      evidence: Source states that attackers with project write access can exploit the vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenPanel js-runtime beyond commit bad75bdd.
      owner: IT Operations
      addresses: CVE-2026-93985
      evidence: NVD vulnerability identifier CVE-2026-93985
---

CVE-2026-93985 describes a critical sandbox escape vulnerability in the OpenPanel js-runtime, affecting all versions up to commit bad75bdd. The vulnerability resides within the JavaScript webhook template validator, which does not properly restrict computed member access to constructor chains. By leveraging computed property notation within a webhook template, an authenticated attacker with project write access can bypass sandbox restrictions to reach the Function constructor. This allows for the execution of arbitrary JavaScript code within the context of the underlying worker process. This vulnerability is highly impactful due to the direct escalation from project-level write access to system-level code execution within the worker environment.

## Attack Chain

1. Attacker gains authenticated access to an OpenPanel instance with 'project write' permissions.
2. Attacker navigates to the webhook template management interface.
3. Attacker crafts a malicious JavaScript payload utilizing computed property notation (e.g., [constructor]).
4. Attacker saves the payload into a webhook template.
5. The OpenPanel js-runtime triggers the validator to process the template.
6. The validator fails to block the access to the Function constructor chain.
7. The runtime executes the attacker-controlled code within the worker process.

## Impact

Successful exploitation grants an attacker arbitrary code execution capabilities within the worker process of the OpenPanel js-runtime. This could lead to sensitive data exfiltration, lateral movement within the infrastructure, or service disruption. Given the high CVSS score of 9.9, the risk to organizations utilizing OpenPanel for webhook management is critical, as it bypasses intended security boundaries.

## Recommendation

Prioritized actions for security teams:
- Identify and audit all existing webhook templates created or modified by non-administrative users.
- Patch OpenPanel js-runtime to a version beyond commit bad75bdd immediately once a fix is provided by the vendor.
- Implement strict ingress filtering for the OpenPanel management interface to limit potential unauthorized project-level access.
- Review worker process permissions to enforce the principle of least privilege, minimizing the potential impact of an arbitrary code execution event.
