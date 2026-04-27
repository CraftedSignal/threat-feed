---
title: NocoBase plugin-workflow-javascript Sandbox Escape Vulnerability
slug: 2026-04-nocobase-rce
description: A remote code execution vulnerability exists in NocoBase plugin-workflow-javascript versions up to 2.0.23 due to a sandbox escape in the createSafeConsole function, allowing unauthenticated attackers to potentially execute arbitrary code on the server.
date: "2026-04-14T12:00:00Z"
severities:
  - critical
exploited: true
tags:
  - nocobase
  - rce
  - sandbox-escape
  - cve-2026-6224
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6224
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6224
  - https://github.com/Pai-777/ai-cve/blob/main/docs/cve-drafts/nocobase-workflow-javascript-sandbox-escape.en.md
  - https://vuldb.com/vuln/357142
rules:
  - title: Detect Suspicious NocoBase Workflow JavaScript Activity
    description: Detects potential exploitation attempts targeting the NocoBase plugin-workflow-javascript sandbox escape vulnerability (CVE-2026-6224) by monitoring for requests to the vulnerable Vm.js file.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect NocoBase createSafeConsole Access
    description: Detects potential exploitation attempts by looking for access to the createSafeConsole component in NocoBase
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security flaw, identified as CVE-2026-6224, affects NocoBase plugin-workflow-javascript versions up to 2.0.23. This vulnerability resides in the `createSafeConsole` function within the `packages/plugins/@nocobase/plugin-workflow-javascript/src/server/Vm.js` file. By manipulating this function, an attacker can escape the intended sandbox environment. Publicly available exploits exist, increasing the risk of active exploitation. This vulnerability allows for remote, unauthenticated…
