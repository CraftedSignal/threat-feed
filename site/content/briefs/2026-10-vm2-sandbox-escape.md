---
title: Critical Sandbox Escape in vm2 via Node.js Buffer Pool
slug: 2026-10-vm2-sandbox-escape
description: A vulnerability in the vm2 library (CVE-2026-92947) allows sandboxed code to bypass security boundaries by reading and writing to the host-realm memory shared through Node.js Buffer pools.
date: "2026-10-06T00:44:32Z"
lastmod: "2026-10-06T00:45:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:vm2_project:vm2:*:*:*:*:*:node.js:*:*
tags:
  - sandbox-escape
  - nodejs
  - vulnerability
  - privilege-escalation
  - denial-of-service
  - sandbox
  - javascript
  - cve-2026-100722
products:
  - vm2 (<= 3.11.6)
  - vm2 (<= 3.12.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: The sandbox can acquire an ArrayBuffer used by the host and disclose sensitive data or write to host buffers.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The exploit uses the JavaScript VM.run method to execute an untrusted script that exploits the bridge construct trap.
    confidence_band: high
cves:
  - id: CVE-2026-92947
    cvss: 10
    epss: 0.00482
references:
  - https://github.com/advisories/GHSA-fcqc-726x-5wfc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92947
  - https://github.com/advisories/GHSA-2v2p-6j97-cjg9
action_plan:
  priority: immediate_escalation
  owners:
    - Detection Engineering
    - IT Operations
  immediate_actions:
    - action: Inventory all applications using vm2 (<= 3.11.6) and initiate an immediate upgrade plan to remove the library or apply vendor-provided patches.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-92947 affects all versions of vm2 up to 3.11.6.
  mitigation_plan:
    - priority: immediate
      action: Update vm2 to 3.11.7 or later
      owner: IT Operations
      addresses: CVE-2026-92947
      evidence: GHSA-fcqc-726x-5wfc
updates:
  - at: "2026-10-06T00:45:58Z"
    level: L1
    summary: added coverage for vm2 (<= 3.12.1)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-2v2p-6j97-cjg9
---

The vm2 library, a popular JavaScript sandbox for Node.js, contains a critical security vulnerability (CVE-2026-92947) that enables sandbox escape. The flaw arises because vm2 exposes the Node.js `Buffer` object to sandboxed code by default. In Node.js, small `Buffer` allocations - including `Buffer.from`, `Buffer.concat`, and `Buffer.allocUnsafe` - utilize a shared internal memory pool. Because the sandbox and host share this pool, an attacker capable of executing arbitrary code within the vm2 sandbox can reference the underlying `ArrayBuffer` used by the host process. This allows the attacker to read host memory, leading to sensitive data disclosure, or write to host memory, potentially corrupting application state and leading to denial-of-service or further privilege escalation. This affects all versions of vm2 up to and including 3.11.6.

## Impact

The vulnerability allows for the cross-realm disclosure of sensitive data processed by the host application, such as authentication tokens, user data, or API keys. Furthermore, the ability for an attacker to perform unauthorized writes to the host-realm memory provides a vector for full sandbox escape, as an attacker can manipulate host process objects or execute arbitrary code outside the restricted sandbox environment. This poses a significant risk to any application that uses vm2 to evaluate untrusted user-provided JavaScript code.

## Recommendation

- Upgrade the vm2 package to the latest version that addresses CVE-2026-92947, or if no patch is available, migrate to a more secure sandboxing alternative.
- Implement strict input validation and sanitization for all code passed into the vm2 sandbox, though this is not a complete mitigation for the identified memory-sharing flaw.
- Apply the principle of least privilege to the Node.js host process by limiting access to sensitive memory, files, and network resources to reduce the potential impact of a sandbox escape.
