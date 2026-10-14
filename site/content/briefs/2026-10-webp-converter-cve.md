---
title: OS Command Injection in webp-converter via libwebp Helpers
slug: 2026-10-webp-converter-cve
description: The webp-converter package before 3.0.0 is vulnerable to OS command injection due to unsafe execution of libwebp binaries via execFile with shell enabled.
date: "2026-10-14T16:33:04Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:webp-converter_project:webp-converter:*:*:*:*:*:node.js:*:*
products:
  - webp-converter (< 3.0.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers controlling file names or option strings passed to cwebp, dwebp, gwebp, or webpmux functions can inject shell metacharacters to execute OS commands.
    confidence_band: high
cves:
  - id: CVE-2026-110635
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110635
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade webp-converter dependency to 3.0.0 or later.
      owner: IT Operations
      addresses: CVE-2026-110635
      evidence: Source explicitly identifies vulnerability in versions before 3.0.0.
---

The webp-converter package prior to version 3.0.0 contains an OS command injection vulnerability located within the src/webpconverter.js helper functions. The vulnerability originates from the package's implementation of libwebp binary execution, specifically using Node.js execFile methods with shell-enabled parameters. This flaw allows an attacker who can influence the input arguments, such as file paths or conversion options passed to cwebp, dwebp, gwebp, or webpmux, to escape the intended binary execution context and inject arbitrary OS commands. Successful exploitation results in remote code execution under the privileges of the Node.js process, posing a significant risk to applications that process user-supplied image files or configurations using this library.

## Attack Chain

1. Attacker identifies an application using webp-converter (< 3.0.0) to process image uploads or user-defined conversion settings.
2. Attacker provides a crafted input string (e.g., a malicious filename or option) containing shell metacharacters such as semicolon, pipe, or ampersand.
3. The target application passes this attacker-controlled input to one of the affected helper functions (cwebp, dwebp, gwebp, or webpmux).
4. The src/webpconverter.js module triggers an execFile operation with the shell option enabled, failing to sanitize the inputs.
5. The underlying shell interpreter parses the metacharacters and executes the injected payload alongside or instead of the intended binary command.
6. Arbitrary commands execute in the context of the Node.js application process, leading to system compromise.

## Impact

Successful exploitation allows unauthenticated remote code execution. This vulnerability is applicable to any environment running a Node.js application that integrates webp-converter, potentially impacting web servers, file processing microservices, and image manipulation pipelines. The CVSS base score of 9.8 reflects the high potential for full system compromise.

## Recommendation

* Update webp-converter to version 3.0.0 or later to apply the security patch.
* Audit application code for any unsanitized user inputs that are subsequently passed as arguments to webp-converter functions.
* Implement strict input validation or allowlisting for all filenames and configuration options processed by image conversion utilities.
