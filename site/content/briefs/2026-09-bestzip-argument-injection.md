---
title: Argument Injection in bestzip nativeZip Function
slug: 2026-09-bestzip-argument-injection
description: The bestzip package version 2.2.6 and 3.0.2 is vulnerable to argument injection in the nativeZip function, allowing unauthenticated attackers to execute arbitrary commands via malicious input.
date: "2026-09-09T10:50:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bestzip_project:bestzip:2.2.6:*:*:*:*:node.js:*:*
  - cpe:2.3:a:bestzip_project:bestzip:3.0.2:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - remote-code-execution
  - nodejs
  - software-supply-chain
products:
  - bestzip (2.2.6, 3.0.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can supply a malicious destination path combined with crafted source entries to execute arbitrary commands with Node.js process privileges.
    confidence_band: high
cves:
  - id: CVE-2026-87794
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87794
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade bestzip to version 2.2.7 or 3.0.3
      owner: IT Operations
      addresses: CVE-2026-87794
      evidence: Fixed in 2.2.7 and 3.0.3.
---

CVE-2026-87794 describes an argument injection vulnerability within the bestzip Node.js package, specifically affecting versions 2.2.6 and 3.0.2. The vulnerability exists in the nativeZip function, which fails to properly sanitize user-supplied input before passing it to the underlying Info-ZIP backend. An attacker can exploit this by providing a specially crafted destination path or source entry that forces the backend utility to interpret data as command-line flags. This allows for the execution of arbitrary system commands running with the security context and privileges of the Node.js process. This vulnerability is highly relevant for any environment utilizing bestzip for file archival within backend APIs or build pipelines. Remediation requires updating to bestzip version 2.2.7 or 3.0.3, which implement stricter input validation within the nativeZip function.

## Impact

Successful exploitation allows remote attackers to execute arbitrary system commands on the host machine. This can lead to full system compromise, exfiltration of sensitive data, or lateral movement within the network, depending on the privileges and environment where the Node.js application is running.

## Recommendation

* Update all instances of the bestzip package to version 2.2.7 or 3.0.3 immediately to address CVE-2026-87794.
* Audit application code to identify if user-controlled input reaches the nativeZip function directly.
* Apply the Principle of Least Privilege by running Node.js applications as low-privileged service accounts to limit the potential impact of command execution vulnerabilities.
