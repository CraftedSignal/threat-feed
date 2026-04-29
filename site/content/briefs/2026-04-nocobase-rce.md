---
title: NocoBase plugin-workflow-javascript Sandbox Escape Vulnerability
slug: 2026-04-nocobase-rce
description: A remote code execution vulnerability exists in NocoBase plugin-workflow-javascript versions up to 2.0.23 due to a sandbox escape in the createSafeConsole function, allowing unauthenticated attackers to potentially execute arbitrary code on the server.
date: "2026-04-14T12:00:00Z"
type: threat
types:
  - threat
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

A critical security flaw, identified as CVE-2026-6224, affects NocoBase plugin-workflow-javascript versions up to 2.0.23. This vulnerability resides in the `createSafeConsole` function within the `packages/plugins/@nocobase/plugin-workflow-javascript/src/server/Vm.js` file. By manipulating this function, an attacker can escape the intended sandbox environment. Publicly available exploits exist, increasing the risk of active exploitation. This vulnerability allows for remote, unauthenticated exploitation, making it a significant threat to systems running the affected NocoBase plugin. The vendor has not responded to vulnerability disclosure attempts.

## Attack Chain

1.  The attacker sends a malicious request to the NocoBase server targeting the `plugin-workflow-javascript` component.
2.  The request is processed by the vulnerable `createSafeConsole` function within `Vm.js`.
3.  The attacker leverages the identified manipulation technique to bypass the intended sandbox restrictions.
4.  The attacker gains unauthorized access to the underlying server environment.
5.  The attacker injects and executes arbitrary JavaScript code within the server context.
6.  The attacker escalates privileges to gain further control of the system.
7.  The attacker establishes persistence through creating new user accounts or modifying system configurations.
8.  The attacker achieves arbitrary code execution on the server, leading to potential data theft, system compromise, or denial of service.

## Impact

Successful exploitation of CVE-2026-6224 can lead to complete compromise of the NocoBase server. An attacker can gain unauthorized access to sensitive data, modify system configurations, install malware, or disrupt normal operations. Given the nature of NocoBase as a data management platform, the impact could include widespread data breaches and significant reputational damage. Because exploits are publicly available, organizations using vulnerable versions of the plugin are at immediate risk.

## Recommendation

*   Upgrade NocoBase plugin-workflow-javascript to a patched version beyond 2.0.23 to remediate CVE-2026-6224.
*   Deploy the provided Sigma rule `Detect Suspicious NocoBase Workflow JavaScript Activity` to identify potential exploitation attempts targeting the `createSafeConsole` function.
*   Monitor web server logs for suspicious requests targeting the `/packages/plugins/@nocobase/plugin-workflow-javascript/src/server/Vm.js` path.
*   Implement strict input validation and sanitization measures to prevent malicious code injection.
