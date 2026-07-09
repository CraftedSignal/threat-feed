---
title: YesWiki Bazar Admin Server-Side Template Injection to RCE (CVE-2026-52762)
slug: 2026-07-yeswiki-ssti-rce
description: An authenticated administrator can exploit a Server-Side Template Injection (SSTI) vulnerability (CVE-2026-52762) in YesWiki Bazar's semantic templates to achieve Remote Code Execution (RCE) on the underlying server, allowing for full system compromise.
date: "2026-07-09T20:56:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - yeswiki
  - ssti
  - rce
  - web-application
  - php
  - cve
vendors:
  - YesWiki
products:
  - YesWiki 4.x (versions < 4.6.6)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated administrator can place arbitrary Twig expressions into the Semantic template (Twig) field (`bn_sem_template`), and that content is later executed server-side when public semantic endpoints are requested.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: In the validated local environment, the stored Twig payload reached full operating-system-level command execution.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: In practical terms, YesWiki administrator privileges become sufficient to obtain command execution on the server in affected deployments.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-65p8-9433-jpcp
rules:
  - title: Detect YesWiki Bazar RCE via Suspicious Web Server Child Process (CVE-2026-52762)
    description: 'CVE-2026-52762: Detects suspicious process creation by the YesWiki web server process, indicative of Remote Code Execution (RCE) post-exploitation of the Server-Side Template Injection (SSTI) vulnerability.'
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical Server-Side Template Injection (SSTI) vulnerability, tracked as CVE-2026-52762, exists in YesWiki Bazar versions prior to 4.6.6. This flaw allows an authenticated administrator to inject arbitrary Twig expressions into semantic template fields (`bn_sem_template` or `bn_sem_reverse_template`). These stored payloads are then executed server-side when public semantic endpoints are requested, leading to confirmed Remote Code Execution (RCE). The attack is persistent as the malicious template is saved in the application's configuration, and it can be triggered remotely by requests to public endpoints such as `/api/forms/{id}/entries/json-ld`. This enables an attacker with administrative access to escalate privileges from application-level control to full operating system compromise. The vulnerability was confirmed through proof-of-concept testing, demonstrating both arbitrary Twig execution and the establishment of an interactive shell on the compromised host.

## Attack Chain

1. An authenticated YesWiki administrator accesses the Bazar form management interface to edit an existing form (e.g., form ID 2).
2. The administrator crafts and injects a malicious Twig expression (e.g., a reverse shell payload or a `system()` call) into the `Semantic template (Twig)` field (`bn_sem_template` or `bn_sem_reverse_template`).
3. YesWiki's backend saves this malicious payload in the application's form configuration database, establishing persistence.
4. A subsequent HTTP GET request, which can be unauthenticated, is made to a public semantic endpoint, such as `/api/forms/{id}/entries/json-ld` (e.g., `GET /api/forms/2/entries/json-ld`).
5. The YesWiki application attempts to render the form's semantic template using the vulnerable `TemplateEngine::renderFromStringNoEscape()` function.
6. During the rendering process, the server-side Twig engine processes and executes the previously stored malicious expression, leading to the execution of arbitrary system commands on the server.
7. The attacker receives an inbound connection (e.g., a reverse shell), establishing an interactive shell session on the YesWiki host.
8. The attacker gains full operating-system-level control over the underlying server, enabling further actions like lateral movement or data exfiltration.

## Impact

Successful exploitation of CVE-2026-52762 allows an authenticated administrator to achieve full Remote Code Execution on the YesWiki server. This critical vulnerability breaks the expected trust boundary, enabling an attacker with administrative application access to pivot to full interactive shell access and system-level compromise. The consequences include unauthorized access to sensitive data, modification or deletion of system files, deployment of malware, and complete control over the compromised server, effectively bypassing application-level security controls.

## Recommendation

* Immediately upgrade YesWiki to version 4.6.6 or later to apply the patch for CVE-2026-52762.
* Deploy the provided Sigma rule to your SIEM to detect suspicious process creation indicative of post-exploitation RCE attempts originating from the web server.
* Review web server logs for suspicious HTTP requests to `/api/forms/*/entries/json-ld` that may indicate exploitation attempts, especially if followed by unusual outbound network activity from the web server's host.
