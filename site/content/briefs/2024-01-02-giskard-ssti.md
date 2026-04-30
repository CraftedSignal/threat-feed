---
title: Giskard-agents ChatWorkflow.chat() Server-Side Template Injection
slug: 2024-01-02-giskard-ssti
description: Giskard-agents versions 0.3.3 and earlier, and versions 1.0.1a1 through 1.0.2a1 are vulnerable to remote code execution via server-side template injection where the ChatWorkflow.chat() method passes user-supplied strings directly to a non-sandboxed Jinja2 Environment, allowing attackers to execute arbitrary code on the server.
date: "2026-03-27T22:17:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssti
  - jinja2
  - rce
  - giskard-agents
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-frv4-x25r-588m
rules:
  - title: Detect Giskard Agents SSTI Attempt via Jinja2 Class Traversal
    description: Detects attempts to exploit the Jinja2 template injection vulnerability in Giskard-agents by identifying class traversal patterns in HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Giskard Agents SSTI Attempt via OS Popen
    description: Detects attempts to exploit the Jinja2 template injection vulnerability in Giskard-agents by identifying usage of os.popen in HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The giskard-agents library, specifically versions 0.3.3 and earlier, along with versions 1.0.1a1 through 1.0.2a1, contains a critical vulnerability related to server-side template injection. The `ChatWorkflow.chat()` method within the library directly passes user-provided strings to a non-sandboxed Jinja2 Environment. This design flaw allows a malicious actor to inject arbitrary Jinja2 templates into the message, which, when rendered, can lead to remote code execution (RCE) on the server hosting the application. This vulnerability exists because the `chat()` method, intended for processing user input, inadvertently interprets the input as a Jinja2 template due to the usage of `_inline_env.from_string()`. Defenders should be aware of applications using the vulnerable `chat()` method which creates the attack surface.

## Attack Chain

1.  Attacker crafts a malicious string containing a Jinja2 payload designed for RCE.
2.  The attacker inputs the malicious string into a user interface or API endpoint that utilizes the `ChatWorkflow.chat()` method.
3.  The application passes the attacker-controlled string to the `ChatWorkflow.chat()` method.
4.  `ChatWorkflow.chat()` creates a `MessageTemplate` object with the attacker's string as the `content_template`.
5.  The `render()` method of the `MessageTemplate` object calls `_inline_env.from_string()` on the attacker-controlled string, creating a Jinja2 template.
6.  The `template.render()` method is invoked, executing the attacker's Jinja2 payload due to the non-sandboxed Jinja2 Environment.
7.  The attacker's payload leverages Jinja2 class traversal to gain access to sensitive modules like `os`.
8.  The attacker executes arbitrary system commands via `os.popen()` (or equivalent), achieving remote code execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary system commands on the server hosting the affected application. This could lead to complete compromise of the server, including data theft, modification, or destruction. The severity of the impact is critical, potentially affecting any application that relies on giskard-agents for chatbot functionality and exposes the `ChatWorkflow.chat()` method to user input. Affected versions include giskard-agents <=0.3.3 and 1.0.x alpha. Patched versions are giskard-agents 0.3.4 (stable) and 1.0.2b1 (pre-release).

## Recommendation

*   Upgrade giskard-agents to version 0.3.4 or 1.0.2b1, which includes the fix mitigating the vulnerability described in this brief.
*   Deploy the Sigma rule `Detect Giskard Agents SSTI Attempt via Jinja2 Class Traversal` to detect exploitation attempts via `webserver` logs.
*   If upgrading is not immediately feasible, sanitize user inputs passed to the `ChatWorkflow.chat()` method to prevent Jinja2 template injection.
