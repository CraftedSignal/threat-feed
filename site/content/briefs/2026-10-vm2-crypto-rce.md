---
title: Arbitrary Native Code Execution in vm2 via crypto.setEngine
slug: 2026-10-vm2-crypto-rce
description: The vm2 sandbox library (v3.11.3-3.11.6) allows attackers to bypass restrictions and execute arbitrary native code in the host process by calling crypto.setEngine() with a path to a malicious dynamic library.
date: "2026-10-01T20:20:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:openjs_foundation:vm2:*:*:*:*:*:*:*:*
tags:
  - sandbox-escape
  - remote-code-execution
  - nodejs
  - supply-chain
vendors:
  - OpenJS Foundation
products:
  - vm2 (3.11.3 - 3.11.6)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The native library's constructor executes before OpenSSL finishes validating whether the file is a usable engine.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The code runs with the operating-system identity and privileges of the Node.js host process, outside all vm2 language and module restrictions.
    confidence_band: high
cves:
  - id: CVE-2026-92939
    cvss: 9.9
    epss: 0.00616
references:
  - https://github.com/advisories/GHSA-46pr-c5wc-xffx
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-92939
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch vm2 to 3.11.7 or later
      owner: Security Engineering
      due: 24h
      evidence: Source confirms versions 3.11.3-3.11.6 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Upgrade vm2 to 3.11.7 or later
      owner: IT Operations
      addresses: CVE-2026-92939
      evidence: Source identifies vulnerability in vm2 versions 3.11.3-3.11.6.
---

The vm2 library, specifically versions 3.11.3 through 3.11.6, contains a critical vulnerability (CVE-2026-92939) that permits sandbox escape and arbitrary native code execution. The vulnerability arises from how vm2 exposes Node.js built-in modules to the sandboxed environment. While vm2 uses a read-only proxy to prevent modification of module properties, it does not restrict the authority of callable exports.

The `crypto.setEngine()` function is exposed to the sandbox when `crypto` is an allowed builtin. This function accepts a filesystem path and instructs OpenSSL to load the referenced dynamic library as a cryptographic engine. Crucially, the operating system's dynamic loader executes the library's constructor logic before OpenSSL performs any validation of the library's validity as a cryptographic engine. An attacker providing a malicious package can place a dynamic library on disk and trigger its execution from the sandbox, gaining the privileges of the host process regardless of other sandboxing restrictions.

## Attack Chain

1. Attacker crafts a malicious package containing a compiled native dynamic library (e.g., .so or .dylib).
2. Attacker provides the package to an application that processes untrusted plugins (e.g., code runner, automation platform).
3. The application saves the package contents to the local filesystem.
4. The application initializes a `NodeVM` instance, granting access to the `crypto` builtin but restricting other modules.
5. The attacker's JavaScript code within the `NodeVM` calls `crypto.setEngine(pathToBundledLibrary)`.
6. vm2 forwards the call to the host-realm `crypto.setEngine` function.
7. The host process loads the attacker's dynamic library via the operating system's native loader.
8. The library's constructor executes arbitrary native code within the host process, achieving full system compromise.

## Impact

This vulnerability allows for a complete sandbox escape, granting the attacker the operating-system identity and permissions of the host Node.js process. Potential impact includes unauthorized access to environment variables, application secrets, credentials, and internal data. Attackers can modify application code, establish persistence, access internal network services, steal data from other tenants sharing the same process, or perform any action permitted to the host user account.

## Recommendation

Prioritize upgrading all instances of the affected vm2 package.
- Upgrade vm2 to a version beyond 3.11.6 immediately, as there are no configuration-based mitigations that safely allow the `crypto` builtin while preventing this attack vector.
- Audit all applications utilizing `vm2` for `NodeVM` configurations that grant access to the `crypto` builtin, specifically in multi-tenant or untrusted plugin scenarios.
- Implement process-level sandboxing (e.g., containerization, gVisor, or restricted service accounts) to limit the potential impact of native code execution if an application remains vulnerable.
