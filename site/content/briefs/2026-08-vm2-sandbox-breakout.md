---
title: Critical Sandbox Escape Vulnerability in vm2
slug: 2026-08-vm2-sandbox-breakout
description: The vm2 sandbox library is vulnerable to a sandbox breakout (CVE-2026-47698) due to insufficient validation of indirect calls, allowing attackers to execute arbitrary system commands on the host.
date: "2026-08-17T18:45:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Patrik Simek
products:
  - vm2 (<= 3.11.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.006
    technique_name: 'Command and Scripting Interpreter: PowerShell'
    evidence: An attacker can manipulate prototype getters and setters via Buffer.call chains to escape the sandbox and execute arbitrary commands on the host system via the child_process module.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-cfcw-xp6x-25gj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-47698
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Identify and patch all instances of vm2 <= 3.11.5 across internal repositories and production services.
      owner: Development
      due: 24h
      evidence: 'Affected Packages: npm/vm2 (vulnerable: <= 3.11.5)'
---

The vm2 library, a common JavaScript sandbox utility, is susceptible to a critical sandbox breakout vulnerability identified as CVE-2026-47698. This issue arises because the library's mitigation for previous sandbox escapes was insufficient; specifically, the input validation logic failed to account for indirect function calls constructed via specific `Buffer.call` chains. 

An attacker capable of executing arbitrary JavaScript within the vm2 context can leverage this flaw to manipulate object prototypes and bypass sandbox restrictions. By exploiting the `WebAssembly.compileStreaming` mechanism and triggering exceptions, an attacker can access the host's `process` object. This grants the ability to utilize Node.js modules like `child_process` to execute arbitrary commands on the host system, effectively bypassing the security isolation boundary. This vulnerability affects all versions of vm2 up to and including 3.11.5. Organizations utilizing this library for untrusted code execution are at significant risk of remote code execution.

## Impact

Successful exploitation leads to full Remote Code Execution (RCE) on the host environment where the vm2-sandboxed code is running. This allows an attacker to bypass all intended isolation restrictions, potentially leading to unauthorized data access, system compromise, or lateral movement within the infrastructure hosting the Node.js application.

## Recommendation

- Upgrade the vm2 package to a version that contains the patch for CVE-2026-47698.
- Review all applications utilizing vm2 for untrusted input and evaluate migration to modern alternative sandboxing solutions, as vm2 has historically suffered from repeated sandbox escape vulnerabilities.
- Implement process-level sandboxing (such as containers or gVisor) to provide defense-in-depth, ensuring that even if a language-level sandbox is breached, the attacker remains contained within a restricted environment.
