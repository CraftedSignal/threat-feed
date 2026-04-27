---
title: Giskard-agents ChatWorkflow.chat() Server-Side Template Injection
slug: 2024-01-02-giskard-ssti
description: Giskard-agents versions 0.3.3 and earlier, and versions 1.0.1a1 through 1.0.2a1 are vulnerable to remote code execution via server-side template injection where the ChatWorkflow.chat() method passes user-supplied strings directly to a non-sandboxed Jinja2 Environment, allowing attackers to execute arbitrary code on the server.
date: "2026-03-27T22:17:30Z"
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

The giskard-agents library, specifically versions 0.3.3 and earlier, along with versions 1.0.1a1 through 1.0.2a1, contains a critical vulnerability related to server-side template injection. The `ChatWorkflow.chat()` method within the library directly passes user-provided strings to a non-sandboxed Jinja2 Environment. This design flaw allows a malicious actor to inject arbitrary Jinja2 templates into the message, which, when rendered, can lead to remote code execution (RCE) on the server…
