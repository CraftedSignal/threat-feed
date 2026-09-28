---
title: Sandbox Escape in vm2 via NodeVM Module Resolver
slug: 2026-09-vm2-sandbox-escape
description: CVE-2026-100721 is a sandbox escape vulnerability in vm2 versions before 3.12.2, allowing untrusted guest code to execute arbitrary code in the host context via an authorization bypass in the external-module resolver.
date: "2026-09-27T05:03:42Z"
lastmod: "2026-09-28T10:18:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vm2_project:vm2:*:*:*:*:*:node.js:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=E4676EF8-66BD-52E8-A048-1B70924F40C5&utm_source=rss&utm_medium=rss
tags:
  - vm2
  - sandbox-escape
  - nodejs
  - code-execution
  - memory-corruption
products:
  - vm2 (< 3.12.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Untrusted guest code can therefore require the allowlisted module and then require the absolute path of a non-allowlisted sibling... resulting in a sandbox escape and arbitrary code execution in the host context.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Untrusted guest code can construct a full-width view of that ArrayBuffer to read and modify bytes belonging to unrelated host buffers, disclosing and corrupting host-realm memory across the sandbox boundary.
    confidence_band: high
cves:
  - id: CVE-2026-100721
    cvss: 9
    epss: 0.004
  - id: CVE-2026-100723
    cvss: 7.5
    epss: 0.00316
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100721
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100723
  - https://sploitus.com/exploit?id=E4676EF8-66BD-52E8-A048-1B70924F40C5&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade vm2 to 3.12.2 or later in all Node.js projects
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-100721 fix requirement
  mitigation_plan:
    - priority: immediate
      action: Patch vm2 to 3.12.2 or later
      owner: Application Security
      addresses: CVE-2026-100721
      evidence: Vendor vulnerability fix notification
updates:
  - at: "2026-09-27T05:03:54Z"
    level: L2
    summary: added coverage for vm2 (< 3.12.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100723
  - at: "2026-09-28T10:18:45Z"
    level: L2
    summary: poc_available; added CVE-2026-100723
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=E4676EF8-66BD-52E8-A048-1B70924F40C5&utm_source=rss&utm_medium=rss
---

CVE-2026-100721 identifies a critical sandbox escape vulnerability in the vm2 library (versions prior to 3.12.2). The vulnerability resides in the `NodeVM` external-module resolver when configured with a custom resolver and `context: 'host'`. The `LegacyResolver.customResolve` function in `lib/resolver-compat.js` improperly validates module paths by creating a regular expression that lacks path separators or end-of-string boundaries.

This flaw allows an attacker to bypass security restrictions by providing a path that shares a prefix with an allowlisted module. For example, if 'foo' is allowlisted, an attacker can require a sibling module 'foo2' located in an absolute path that starts with the same prefix. The vulnerable resolver treats this as authorized, loading the non-allowlisted module into the host process. The top-level code of the malicious module executes before the guest exports are wrapped, enabling full host-context code execution. This is particularly dangerous for applications using vm2 to sandboxing untrusted scripts.

## Impact

Successful exploitation allows arbitrary code execution on the host machine hosting the Node.js application. This bypasses the intended security boundaries of the vm2 sandbox, potentially leading to full server compromise, data exfiltration, or lateral movement within the environment. Any application leveraging vm2 for processing user-supplied code is highly susceptible to this sandbox escape.

## Recommendation

* Upgrade the vm2 dependency to version 3.12.2 or higher to include the fix for the resolver path validation logic.
* Audit applications currently utilizing the NodeVM 'context: host' configuration and a custom 'require.external' resolver to identify potential exposure.
* Implement strict path sanitization or validation wrappers if immediate library updates are not feasible, though upgrading remains the primary defense.
