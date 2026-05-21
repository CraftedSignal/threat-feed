---
title: KnpLabs knp-snappy Command Injection Vulnerability (CVE-2026-46643)
slug: 2026-05-snappy-command-injection
description: KnpLabs knp-snappy versions 1.7.0 and earlier are vulnerable to command injection (CVE-2026-46643) due to an inverted is_executable check, which prevents proper shell escaping of the binary path, potentially leading to command execution if the binary path is attacker-influenced.
date: "2026-05-21T20:23:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - php
  - knp-snappy
  - CVE-2026-46643
vendors:
  - KnpLabs
products:
  - knp-snappy (<= 1.7.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://github.com/advisories/GHSA-vpr4-p6fq-85jc
rules:
  - title: Detect knp-snappy Command Injection Attempt
    description: Detects CVE-2026-46643 exploitation — attempts to exploit command injection in knp-snappy by detecting shell metacharacters in process command lines involving wkhtmltopdf
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect knp-snappy Command Injection Attempt (Linux)
    description: Detects CVE-2026-46643 exploitation — attempts to exploit command injection in knp-snappy by detecting shell metacharacters in process command lines involving wkhtmltopdf on Linux
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The KnpLabs knp-snappy library, a PHP wrapper for the `wkhtmltopdf` and `wkhtmltoimage` utilities, is susceptible to a command injection vulnerability (CVE-2026-46643) in versions 1.7.0 and earlier. The vulnerability arises from an incorrect implementation of input sanitization, specifically, an inverted `is_executable` check that causes the binary path to bypass shell escaping. This flaw can be exploited when the binary path is derived from user-influenced configuration, environment variables originating from request data, or concatenated with user-controlled fragments. An attacker can inject arbitrary commands into the binary path, leading to command execution on the server. This is a regression, since downstream packages reasonably assume Snappy shell-escapes the binary. The vulnerability was patched in version 1.7.1.

## Attack Chain

1. An attacker identifies a web application utilizing the vulnerable knp-snappy library (version 1.7.0 or earlier) to generate PDFs.
2. The attacker determines that the path to the `wkhtmltopdf` binary is configurable via a user-controlled source (e.g., a configuration file or environment variable).
3. The attacker injects a malicious command into the binary path. For example, setting the binary path to `wkhtmltopdf; touch /tmp/snappy_rce`.
4. The web application uses the knp-snappy library to generate a PDF, passing the attacker-controlled binary path to the `Knp\Snappy\Pdf` constructor.
5. Due to the flawed `is_executable` check, the binary path is not properly shell-escaped.
6. The `wkhtmltopdf` utility is invoked with the injected command.
7. The injected command is executed on the server with the privileges of the PHP process.
8. The attacker achieves arbitrary command execution, potentially leading to further compromise of the system.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the server hosting the vulnerable web application. The impact ranges from reading sensitive files and modifying application data to full system compromise, depending on the permissions of the PHP process. This vulnerability affects applications that rely on knp-snappy for PDF generation and where the binary path is sourced from a user-influenced location. Even if the binary path is hardcoded, this is a defensive-in-depth regression.

## Recommendation

*   Upgrade to knp-snappy version 1.7.1 or later to patch CVE-2026-46643.
*   As a workaround, implement a check using `\is_executable($path)` before calling the `Knp\Snappy\Pdf` constructor to ensure the binary path is valid.
*   Deploy the Sigma rule "Detect knp-snappy Command Injection Attempt" to identify attempts to exploit this vulnerability by detecting shell metacharacters in process command lines.
*   Review all instances where the `wkhtmltopdf` binary path is configured and ensure that user input is properly validated and sanitized to prevent command injection.
