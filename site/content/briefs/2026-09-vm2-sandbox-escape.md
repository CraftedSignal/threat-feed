---
title: Multiple Arbitrary Code Execution Vulnerabilities in vm2
slug: 2026-09-vm2-sandbox-escape
description: Multiple vulnerabilities in the vm2 JavaScript sandbox library, including CVE-2023-30547, CVE-2023-32314, and CVE-2023-32675, allow attackers to escape the sandbox and execute arbitrary code on the host system.
date: "2026-09-04T18:06:45Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:vm2_project:vm2:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:vyperlang:vyper:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - sandbox-escape
  - code-execution
products:
  - vm2 (<= 3.9.16)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Multiple vulnerabilities in the vm2 JavaScript sandbox library allow an attacker to escape the sandbox and execute arbitrary code on the host system.
    confidence_band: high
cves:
  - id: CVE-2023-30547
    cvss: 9.8
    epss: 0.72087
  - id: CVE-2023-32314
    cvss: 9.8
    epss: 0.08127
  - id: CVE-2023-32675
    cvss: 3.7
    epss: 0.00553
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3189
  - https://nvd.nist.gov/vuln/detail/CVE-2023-30547
  - https://nvd.nist.gov/vuln/detail/CVE-2023-32314
  - https://nvd.nist.gov/vuln/detail/CVE-2023-32675
action_plan:
  priority: elevated
  owners:
    - Security Operations
    - Development Teams
  immediate_actions:
    - action: Perform dependency scan to locate all instances of vm2
      owner: Security Operations
      due: 24h
      evidence: Source notes the library is deprecated and vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Replace vm2 library with secure alternatives
      owner: Development Teams
      addresses: CVE-2023-30547, CVE-2023-32314, CVE-2023-32675
      evidence: vm2 is deprecated and contains multiple sandbox escapes.
---

The JavaScript library vm2, widely used for running untrusted code in a sandboxed environment, contains multiple critical vulnerabilities that permit attackers to break out of the sandbox. These vulnerabilities, tracked under CVE-2023-30547, CVE-2023-32314, and CVE-2023-32675, stem from improper sanitization of error objects and mishandling of asynchronous operations. By exploiting these flaws, an attacker can bypass the security boundaries intended to isolate the guest code, leading to arbitrary code execution on the underlying host operating system. Given the library's role in security-sensitive isolation tasks, this risk is severe for any application or platform that processes user-supplied JavaScript using vulnerable versions of the vm2 sandbox. Defenders should prioritize auditing dependencies and migrating to alternative isolation mechanisms, as vm2 has been deprecated due to persistent sandbox escape issues.

## Impact

Successful exploitation allows a guest user to elevate privileges from the sandbox to the host environment. This can lead to full system compromise, data exfiltration, or lateral movement within the network. These flaws impact a wide range of Node.js applications that utilize vm2 for security-critical sandboxing of user-provided content.

## Recommendation

Identify all applications within the environment that utilize the vm2 library via software composition analysis tools. Since the library is deprecated and no longer receives security updates, migration to a more secure isolation alternative such as Web Workers or dedicated virtual machines is required. Review all instances of code executing user-supplied JavaScript to ensure the sandbox is removed or replaced.
