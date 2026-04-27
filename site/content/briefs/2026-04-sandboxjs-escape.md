---
title: SandboxJS Integrity Escape Vulnerability
slug: 2026-04-sandboxjs-escape
description: A sandbox integrity escape vulnerability exists in SandboxJS versions prior to 0.8.36, allowing untrusted code to bypass global write protections and mutate host shared global objects, potentially leading to cross-context persistence and broader compromise.
date: "2026-04-03T21:44:39Z"
severities:
  - critical
tags:
  - sandbox-escape
  - javascript
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-2gg9-6p7w-6cpj
rules:
  - title: Detect SandboxJS Global Object Mutation via Constructor Call
    description: Detects the usage of `this.constructor.call` to modify global objects, indicating a potential SandboxJS escape attempt.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect SandboxJS Constructor Call to Global Objects
    description: Detects calls to the constructor of a SandboxJS object targeting global objects such as Math or JSON.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability exists in SandboxJS versions prior to 0.8.36, a JavaScript sandbox library. This vulnerability allows malicious or untrusted JavaScript code executed within the sandbox to escape the sandbox and modify global objects in the host environment. The bypass is achieved through an exposed callable constructor path: `this.constructor.call(target, attackerObject)`, allowing attackers to circumvent intended protections against direct assignment to global objects. This can lead…
