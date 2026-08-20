---
title: Remote Code Injection in chenhg5 cc-connect
slug: 2026-08-cc-connect-injection
description: An unauthenticated remote code injection vulnerability in the Authenticate function of chenhg5 cc-connect (up to 1.4.1) allows attackers to execute arbitrary code via the exec parameter.
date: "2026-08-20T00:39:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - remote-code-execution
  - injection
  - web-application
vendors:
  - chenhg5
products:
  - cc-connect (1.4.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The manipulation of the argument exec results in code injection.
    confidence_band: high
cves:
  - id: CVE-2026-76760
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76760
  - https://github.com/chenhg5/cc-connect/issues/1488
rules:
  - title: Detects CVE-2026-76760 Exploitation - Code Injection via exec parameter
    description: Detects suspicious HTTP requests to the cc-connect webhook endpoint where the 'exec' parameter contains common shell metacharacters often used in command injection attacks.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch or restrict access to the affected endpoint
      owner: IT Operations
      due: 48h
      evidence: Code injection vulnerability in cc-connect up to 1.4.1
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to block malicious input in the exec parameter
      owner: IT Operations
      addresses: CVE-2026-76760
      evidence: NVD description of injection vector
---

A code injection vulnerability has been identified in chenhg5 cc-connect, affecting all versions up to and including 1.4.1. The vulnerability resides within the 'Authenticate' function located in 'core/webhook.go'. The application fails to properly neutralize user-controlled input passed to the 'exec' argument, allowing an unauthenticated remote attacker to inject and execute arbitrary code. The exploit for this vulnerability is currently public, increasing the risk of exploitation by threat actors targeting this service. Defenders should prioritize patching or restricting access to the affected webhook endpoint to prevent exploitation.

## Impact

Successful exploitation allows for unauthenticated remote code execution on the server hosting the cc-connect service. This grants an attacker the ability to execute arbitrary commands, potentially leading to full system compromise, data exfiltration, or deployment of additional malicious payloads.

## Recommendation

- Upgrade chenhg5 cc-connect to a patched version beyond 1.4.1 immediately.
- If patching is not feasible, implement strict input validation or block access to the 'core/webhook.go' endpoint at the web application firewall (WAF) or ingress proxy level, specifically monitoring for the 'exec' argument containing shell metacharacters.
- Review web server access logs for anomalous requests to webhook endpoints involving the 'exec' parameter.
