---
title: Remote Code Execution in Floci VtlTemplateEngine
slug: 2026-10-floci-rce
description: An unauthenticated remote code execution vulnerability in Floci 1.1.0-2.1.9 allows attackers to achieve command execution via malicious Velocity templates.
date: "2026-10-10T19:55:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:floci:floci:1.1.0:*:*:*:*:*:*:*
vendors:
  - Floci
products:
  - Floci (1.1.0-2.1.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can exploit this via the REST API by creating a MOCK integration with a malicious Velocity template.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: By leveraging '$util' reflection, the attacker can access 'Runtime' or 'ProcessBuilder' classes to execute arbitrary OS commands.
    confidence_band: high
cves:
  - id: CVE-2026-108598
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108598
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Floci to 2.2.0 or later.
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends version 2.2.0 as the fix.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the Floci API management interface.
      owner: IT Operations
      addresses: CVE-2026-108598
      evidence: Unrestricted API access allows exploitation.
---

Floci versions 1.1.0 through 2.1.9 are susceptible to a critical remote code execution vulnerability (CVE-2026-108598) located within the VtlTemplateEngine component. The vulnerability arises from unrestricted processing of Velocity mapping templates used in API integrations. An unauthenticated attacker can exploit this by creating a REST API endpoint configured with a MOCK integration. By injecting malicious Velocity syntax that utilizes '$util' reflection, the attacker can access dangerous Java classes such as 'Runtime' or 'ProcessBuilder'. This allows the execution of arbitrary OS commands with the privileges of the Floci Java Virtual Machine process. This flaw poses a high risk to organizational infrastructure, as it provides a trivial vector for initial access and full system compromise without requiring authentication.

## Attack Chain

1. The attacker identifies an internet-facing instance of Floci.
2. The attacker authenticates or interacts with the public API endpoint, specifically targeting the REST API integration management interface.
3. The attacker creates a new MOCK integration via the Floci REST API.
4. The attacker provides a custom Velocity template containing reflective payload syntax targeting 'java.lang.Runtime' or 'java.lang.ProcessBuilder'.
5. The Floci application saves and subsequently evaluates the malicious template within the VtlTemplateEngine.
6. The VtlTemplateEngine executes the reflected code within the JVM context.
7. The attacker achieves arbitrary command execution on the underlying host operating system.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary system commands, leading to complete compromise of the Floci application host. Potential outcomes include full data exfiltration, persistent unauthorized access, lateral movement within the network, and the deployment of additional malware or ransomware.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

* Upgrade all instances of Floci to version 2.2.0 or later to patch CVE-2026-108598.
* If patching cannot be performed immediately, restrict network access to the Floci API management interface to trusted internal segments only.
* Monitor webserver access logs for anomalous POST requests directed at API integration endpoints, specifically looking for Velocity template syntax or reflective Java keywords in request bodies.
