---
title: Sandbox Escape in heym Expression Engine
slug: 2026-09-heym-sandbox-escape
description: The heym expression engine before version 0.0.91 is vulnerable to a sandbox escape via the DotList map/filter and fallback resolver, allowing authenticated users to achieve arbitrary Python code execution.
date: "2026-09-27T03:08:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:heym:heym:*:*:*:*:*:*:*:*
tags:
  - sandbox-escape
  - code-execution
  - expression-engine
vendors:
  - heym
products:
  - heym (< 0.0.91)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can craft workflow expressions using dunder attribute access through item expressions or the fallback resolver to access os.system and execute commands as the backend process.
    confidence_band: high
cves:
  - id: CVE-2026-100864
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100864
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade heym to version 0.0.91 or later
      owner: IT Operations
      due: 24h
      evidence: Source explicitly identifies versions prior to 0.0.91 as containing the vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade heym platform to version 0.0.91
      owner: IT Operations
      addresses: CVE-2026-100864
      evidence: NVD vulnerability remediation guidance
---

The heym automation and expression engine platform, in versions prior to 0.0.91, contains a critical security flaw involving sandbox escape within its expression processing logic. Specifically, the DotList map/filter functionality and the fallback resolver do not correctly enforce boundary controls on object attribute access. An authenticated attacker can leverage this vulnerability by crafting malicious workflow expressions that utilize Python dunder (double underscore) attributes to traverse the object graph. By accessing these restricted attributes, an attacker can reach the os.system module, ultimately leading to arbitrary code execution within the context of the backend application process. This vulnerability poses a significant risk to organizations using the heym platform for workflow automation, as it allows unauthorized users to transition from limited expression evaluation to full system command execution on the host environment.

## Impact

Successful exploitation allows an authenticated attacker to execute arbitrary system commands as the user running the heym backend process. This impact includes unauthorized access to system files, lateral movement within the hosting infrastructure, and the potential for full control over the automation environment. This vulnerability affects all deployments of heym version 0.0.90 and earlier.

## Recommendation

Prioritized actions for security and infrastructure teams:

* Immediately upgrade all instances of the heym platform to version 0.0.91 or later to remediate the vulnerable expression engine components.
* Audit existing workflow expressions for unusual usage of dunder attributes (e.g., __subclasses__, __globals__, __dict__) within the application logs or configuration repository.
* Restrict access to the workflow creation interface to verified, highly-trusted users only until the patch is deployed, as exploitation requires an authenticated account.
* Monitor backend process activity for suspicious child processes spawned by the main heym application service.
