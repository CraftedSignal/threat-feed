---
title: Roo Code Command Injection Vulnerability (CVE-2026-63108)
slug: 2026-07-roo-code-command-injection
description: A command injection vulnerability in Roo Code versions through 3.54.0 allows attackers to bypass allowlist/denylist enforcement in the auto-approve execute feature. By nesting command substitutions inside parameter expansion defaults, the command parser in parse-command.ts fails to detect the dangerous payloads, leading to their auto-approval and subsequent arbitrary command execution via the shell through execa.
date: "2026-07-20T19:22:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - rce
  - web-vulnerability
  - cve
vendors:
  - Roo Code
products:
  - Roo Code (through 3.54.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: By nesting command substitutions inside parameter expansion defaults...executed by the shell via execa, enabling arbitrary command execution.
    confidence_band: high
cves:
  - id: CVE-2026-63108
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63108
rules:
  - title: Detect CVE-2026-63108 Exploitation Attempt - Roo Code Command Injection
    description: Detects exploitation attempts for CVE-2026-63108, a command injection vulnerability in Roo Code, by identifying patterns indicative of nested command substitutions and parameter expansion in web requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
    data_sources:
      - webserver
rules_count: 1
---

A critical command injection vulnerability, identified as CVE-2026-63108, affects Roo Code versions up to and including 3.54.0. This flaw resides within the "auto-approve execute" feature, which is designed to enforce allowlist or denylist policies for executed commands. Attackers can bypass these security measures by carefully crafting malicious inputs that embed command substitutions within parameter expansion defaults. The underlying command parser, specifically in `parse-command.ts`, fails to correctly identify these nested dangerous payloads. It replaces outer parameter expansions with safe placeholders before scrutinizing for command substitutions, thereby circumventing the `containsDangerousSubstitution` guard. Consequently, the attacker's commands are mistakenly auto-approved and then executed by the system's `execa` utility via the shell, leading to arbitrary command execution on the server. This vulnerability poses a severe risk of remote code execution.

## Attack Chain

1. An attacker identifies a Roo Code application instance that utilizes the "auto-approve execute" feature, which processes user-supplied command parameters.
2. The attacker crafts a malicious input string, embedding command substitutions (e.g., `$()`, `` ` ``) within shell parameter expansion defaults (e.g., `${VAR:-...}`, `${VAR/.../}` ).
3. This crafted input targets a command prefix or structure that is typically allowlisted or implicitly trusted by the "auto-approve execute" feature.
4. The vulnerable `parse-command.ts` component processes the attacker's input, mistakenly replacing the benign-looking outer parameter expansion components with opaque placeholders.
5. Due to this parsing order, the `containsDangerousSubstitution` guard fails to detect the truly malicious nested command substitutions, leading to the payload being auto-approved for execution.
6. The `execa` utility, which is responsible for executing shell commands, receives and processes the auto-approved, malicious command string.
7. The attacker's arbitrary commands are executed on the underlying operating system with the privileges of the Roo Code application, potentially leading to full system compromise, data exfiltration, or other severe impacts.

## Impact

Successful exploitation of CVE-2026-63108 results in arbitrary command execution on the server hosting the Roo Code application. This could allow attackers to execute any command, bypass security controls, steal sensitive data, install backdoors, or disrupt services. The high CVSS v3.1 Base Score of 8.8 reflects the critical nature of this vulnerability, indicating a significant risk to the confidentiality, integrity, and availability of affected systems. Organizations using vulnerable Roo Code versions are at risk of complete system compromise if an attacker can leverage this flaw.

## Recommendation

* Patch CVE-2026-63108 by upgrading Roo Code to a version beyond 3.54.0 immediately.
* Deploy the Sigma rule "Detect CVE-2026-63108 Exploitation Attempt - Roo Code Command Injection" to your SIEM and investigate any generated alerts for signs of compromise.
* Monitor `webserver` logs for patterns indicative of shell metacharacters and command substitution attempts within URL parameters or POST bodies, especially for applications using the "auto-approve execute" feature.
