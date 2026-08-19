---
title: Unauthenticated Remote Code Execution in ICEcoder 8.1
slug: 2026-08-icecoder-rce
description: ICEcoder version 8.1 contains a critical vulnerability allowing unauthenticated remote code execution via a crafted HTTP POST request to the terminal endpoint that chains authentication and CSRF bypasses.
date: "2026-08-19T20:39:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-application-vulnerability
  - rce
  - cve-2026-63722
vendors:
  - ICEcoder
products:
  - ICEcoder (8.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: ICEcoder 8.1 contains an unauthenticated remote code execution vulnerability that allows unauthenticated attackers to execute arbitrary OS commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: An attacker can... execute arbitrary OS commands by chaining an authentication bypass, CSRF validation bypass, and unsanitized command execution.
    confidence_band: high
cves:
  - id: CVE-2026-63722
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63722
rules:
  - title: Detect CVE-2026-63722 Exploitation Attempt
    description: Detects potential exploitation attempts of CVE-2026-63722 by identifying POST requests to the terminal endpoint containing common authentication and CSRF bypass parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch ICEcoder 8.1 instances or restrict access to the terminal endpoint at the network edge.
      owner: IT Operations
      due: 24h
      evidence: Critical severity RCE (CVE-2026-63722).
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF filter for CVE-2026-63722.
      owner: Detection Engineering
      addresses: CVE-2026-63722
      evidence: Unauthenticated RCE vulnerability.
---

ICEcoder version 8.1 is affected by a critical unauthenticated remote code execution (RCE) vulnerability, tracked as CVE-2026-63722. This vulnerability stems from inadequate input validation and security control implementation within the application's terminal functionality. An attacker can exploit this flaw by sending a specially crafted HTTP POST request to the terminal endpoint. By providing a password parameter, the attacker bypasses the authentication mechanism; by including a non-empty CSRF parameter, they circumvent CSRF protection. Finally, the application passes the attacker-supplied command string directly into the PHP proc_open() function. This allows the execution of arbitrary OS commands with the privileges of the web-server process, potentially leading to full server compromise. Given the ease of exploitation, immediate remediation is required for all deployments of ICEcoder 8.1.

## Attack Chain

1. Attacker performs reconnaissance to identify a target web server running ICEcoder 8.1.
2. Attacker crafts an HTTP POST request targeting the application's terminal endpoint.
3. Attacker includes a 'password' parameter in the POST body to bypass initial authentication checks.
4. Attacker includes a non-empty 'csrf' parameter to satisfy the application's CSRF validation logic.
5. Attacker provides the malicious payload within the command parameters destined for the terminal execution flow.
6. The application processes the request, failing to sanitize the command input.
7. The application invokes the underlying PHP proc_open() function with the attacker-controlled input.
8. Arbitrary OS commands execute in the context of the web-server user, resulting in system impact.

## Impact

Successful exploitation of CVE-2026-63722 grants an unauthenticated attacker full remote code execution capabilities on the host server. This allows for data exfiltration, lateral movement within the network, or the installation of persistent backdoors. The impact is assessed as critical, given the ease of triggering the RCE via a single unauthenticated HTTP request.

## Recommendation

1. Immediately upgrade all instances of ICEcoder to a patched version once available to address CVE-2026-63722.
2. Implement WAF rules to inspect HTTP POST requests targeting the ICEcoder terminal endpoint for command injection patterns (e.g., shell operators like ';', '|', '&&').
3. Deploy the Sigma rule below to detect attempts to access the terminal endpoint with known bypass parameters.
