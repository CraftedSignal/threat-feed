---
title: Remote OS Command Injection in orbitale imagemagick-php
slug: 2026-10-imagemagick-php-rce
description: The orbitale imagemagick-php library up to version 3.3.5 is vulnerable to remote OS command injection via the Command::font function in src/Command.php, allowing unauthenticated attackers to execute arbitrary commands.
date: "2026-10-19T22:24:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:orbitale:imagemagick-php:*:*:*:*:*:*:*:*
tags:
  - php
  - rce
  - vulnerability
  - web-application
vendors:
  - orbitale
products:
  - imagemagick-php (<= 3.3.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be executed remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The manipulation of the argument fontFile results in os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-112301
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112301
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify and audit all applications using orbitale imagemagick-php
      owner: IT Operations
      due: 48h
      evidence: Vulnerable library detected in production
  mitigation_plan:
    - priority: immediate
      action: Implement input validation for fontFile parameters
      owner: IT Operations
      addresses: CVE-2026-112301
      evidence: No vendor patch provided for CVE-2026-112301
---

The orbitale imagemagick-php library, which provides a PHP wrapper for ImageMagick, contains a critical OS command injection vulnerability identified as CVE-2026-112301. The flaw exists in the `Command::font` function within `src/Command.php`. An attacker can reach this vulnerable function by providing a specially crafted `fontFile` argument, which is then concatenated into a shell command without adequate sanitization. This vulnerability allows for remote code execution (RCE) on systems where this library is utilized to process user-supplied input. Given that a public exploit exists, defenders should prioritize auditing applications that utilize this package for image processing, as the vendor has not provided a patch for this version range.

## Impact

Successful exploitation of this vulnerability results in full remote OS command execution with the privileges of the PHP process. This can lead to complete system compromise, data exfiltration, and lateral movement within the environment. All applications integrating versions of orbitale imagemagick-php up to 3.3.5 are currently at risk, as there is no vendor-supplied fix available to address this specific command injection vector.

## Recommendation

- Perform an inventory of all applications utilizing orbitale imagemagick-php to identify exposure.
- Implement strict input validation on all user-supplied parameters passed to image processing functions in PHP applications.
- Monitor web server access logs for anomalous requests containing shell metacharacters (e.g., ;, |, &, $, `) directed at endpoints that interface with the `fontFile` parameter.
- If a patch remains unavailable, consider replacing the vulnerable library or implementing a wrapper that strictly sanitizes and escapes all input passed to the library’s functions.
