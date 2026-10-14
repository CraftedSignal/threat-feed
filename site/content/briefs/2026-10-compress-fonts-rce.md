---
title: Command Injection in @offactory/compress-fonts
slug: 2026-10-compress-fonts-rce
description: The @offactory/compress-fonts package before version 1.1.1 is vulnerable to OS command injection via unquoted font file path interpolation in child_process.execSync.
date: "2026-10-14T16:38:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:offactory:compress-fonts:*:*:*:*:*:node.js:*:*
vendors:
  - offactory
products:
  - compress-fonts (< 1.1.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Font paths are interpolated unquoted into a FontForge command run through child_process.execSync, so shell metacharacters in file names execute commands.
    confidence_band: high
cves:
  - id: CVE-2026-110648
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110648
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade @offactory/compress-fonts to version 1.1.1 or later
      owner: Application Security
      addresses: CVE-2026-110648
      evidence: Source provided vulnerability exists in versions < 1.1.1
---

The @offactory/compress-fonts package before version 1.1.1 contains an OS command injection vulnerability (CVE-2026-110648). The flaw exists because the library takes user-supplied font file paths and interpolates them directly into a shell command string without proper quoting or sanitization. This string is then executed via the Node.js child_process.execSync function. By providing a font file with a maliciously crafted name containing shell metacharacters (such as backticks, semicolons, or pipe symbols), an attacker can cause the underlying system to execute arbitrary commands with the privileges of the application process. This vulnerability is particularly critical for server-side applications that process user-uploaded font files for compression.

## Impact

Successful exploitation allows remote attackers to execute arbitrary shell commands on the hosting environment. This can lead to full system compromise, data exfiltration, or the deployment of persistent malware depending on the privileges of the Node.js process. As this is a library-level vulnerability, any application utilizing this package to process untrusted font inputs is at risk.

## Recommendation

* Upgrade the @offactory/compress-fonts dependency to version 1.1.1 or later.
* Audit applications using this package to identify if they process font files from untrusted user sources.
* If upgrading is not immediately possible, implement strict allowlisting for file names and paths before they are passed to the compress-fonts library functions.
