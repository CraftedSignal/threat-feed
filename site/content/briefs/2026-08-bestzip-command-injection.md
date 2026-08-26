---
title: Arbitrary Command Execution in bestzip Library via Argument Injection
slug: 2026-08-bestzip-command-injection
description: The bestzip library improperly handles file paths passed to the system zip utility, allowing attackers to inject command line flags and execute arbitrary code by passing paths beginning with hyphens.
date: "2026-08-26T16:22:02Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - bestzip
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: An application that passes a file name or path it received from an untrusted source into the bestzip API therefore executes a command of the supplier's choosing.
    confidence_band: high
cves:
  - id: CVE-2026-80427
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80427
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Update bestzip library to patched versions 2.2.6 or 3.0.3.
      owner: IT Operations
      due: 72h
      evidence: Versions 2.2.6 and 3.0.2 add the delimiter.
  mitigation_plan:
    - priority: immediate
      action: Identify and sanitize all user-supplied paths passed to bestzip API.
      owner: AppSec
      addresses: CVE-2026-80427
      evidence: An application that passes a file name or path it received from an untrusted source into the bestzip API therefore executes a command.
---

The bestzip library, a Node.js utility for creating zip archives, contains a critical vulnerability (CVE-2026-80427) involving improper argument sanitization when invoking the underlying system 'zip' binary. The library constructs the command line arguments for the zip process without using the '--' delimiter to separate command options from source file operands. 

An attacker who can influence the list of files or paths passed to the bestzip API can provide a file path starting with a hyphen. Because the zip utility processes arguments in order, these attacker-supplied strings are interpreted as command options. By supplying the '-T' and '-TT' flags followed by a malicious command string, an attacker can coerce the zip utility to execute that command via a shell upon completion of the archive operation. This impacts applications that allow users to influence file names or directory paths that are subsequently processed by the bestzip library. Versions 2.2.6 and 3.0.2 introduced a fix by implementing the mandatory '--' delimiter.

## Impact

Successful exploitation allows for arbitrary command execution on the host system with the privileges of the application process running the bestzip library. This vulnerability affects any Node.js application relying on bestzip to process untrusted file inputs, potentially leading to full system compromise, exfiltration of sensitive data, or lateral movement within the environment.

## Recommendation

* Update the bestzip dependency to version 2.2.6 or 3.0.3 (or later) to ensure the '--' delimiter is correctly applied to system calls.
* Audit applications using bestzip to identify if user-provided file names or directory paths are passed to the library functions without server-side validation.
* Implement strict input validation or sanitization for all file paths before they are passed to archive-related APIs.
* Monitor for suspicious child process spawning originating from Node.js applications, specifically targeting the execution of 'zip' or 'unzip' with unusual command line arguments.
