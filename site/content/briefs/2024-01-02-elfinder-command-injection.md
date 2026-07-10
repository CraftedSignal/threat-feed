---
title: elFinder Command Injection via ImageMagick CLI in Resize Command
slug: 2024-01-02-elfinder-command-injection
description: elFinder is vulnerable to command injection via the 'bg' parameter in the resize command when using the ImageMagick CLI backend, allowing arbitrary command execution as the web server process user.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - elFinder
  - command-injection
  - imagemagick
  - webserver
vendors:
  - elFinder
products:
  - elFinder
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-8q4h-8crm-5cvc
rules:
  - title: elFinder Resize Command Injection Attempt
    description: Detects potential command injection attempts in elFinder's resize command by identifying suspicious characters in the 'bg' parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: elFinder ImageMagick Command Injection - Suspicious Background Color
    description: Detects potential elFinder ImageMagick command injection by looking for unusual characters or patterns in the background color parameter.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

elFinder, a web file manager, is susceptible to a command injection vulnerability affecting versions prior to 2.1.67. The vulnerability resides within the `resize` command, specifically how the `bg` (background color) parameter is handled when the ImageMagick CLI backend is used for image processing. User-supplied input for the `bg` parameter is not properly sanitized before being incorporated into shell command strings. This allows an attacker to inject arbitrary commands by crafting a malicious `bg` value, resulting in command execution with the privileges of the web server process. This poses a significant risk to web servers running vulnerable elFinder instances, potentially leading to data breaches, system compromise, or denial of service. The vulnerability was addressed in version 2.1.67 by validating the `bg` parameter against a strict allowlist and safely escaping the value.

## Attack Chain

1. An attacker sends a crafted HTTP request to an elFinder instance, targeting the `resize` command.
2. The request includes a malicious `bg` parameter value containing shell metacharacters.
3. elFinder processes the request and passes the `bg` parameter to the volume resize handling function.
4. The application determines that image processing should use the ImageMagick CLI backend.
5. The application interpolates the unsanitized `bg` parameter value into a shell command string.
6. The injected shell metacharacters are interpreted by the shell, allowing the attacker to inject arbitrary commands.
7. The system executes the crafted shell command with the privileges of the web server process.
8. The attacker achieves arbitrary code execution on the server, potentially leading to data exfiltration or system compromise.

## Impact

Successful exploitation allows an attacker to execute arbitrary operating system commands with the privileges of the web server process. The impact depends on the server configuration, enabled commands, the backend image library selection, and any existing deployment controls. A successful attack could lead to complete system compromise, data breaches, or denial of service. While the specific number of affected installations is unknown, this vulnerability presents a high risk due to the potential for significant damage.

## Recommendation

*   Upgrade elFinder to version 2.1.67 or later to patch the vulnerability.
*   If upgrading is not immediately feasible, disable the `resize` command within elFinder's configuration to prevent exploitation.
*   If `resize` command is needed, avoid using the ImageMagick CLI backend for image processing and use a safer library.
*   Deploy the Sigma rule "elFinder Resize Command Injection Attempt" to detect exploitation attempts based on suspicious characters in the `cs-uri-query` (webserver log source).
*   Monitor web server logs for unusual command invocations originating from the web server process, which could indicate successful exploitation.
