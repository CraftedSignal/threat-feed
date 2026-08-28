---
title: Command Injection Vulnerability in PowSyBl Core
slug: 2026-08-powsybl-command-injection
description: PowSyBl Core is vulnerable to OS command and argument injection (CVE-2026-55673) via unsanitized shell concatenation in its local command execution components, allowing unauthenticated remote command execution.
date: "2026-08-28T21:15:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:powsybl:powsybl_computation_local:*:*:*:*:*:*:*:*
tags:
  - cve-2026-55673
  - command-injection
  - java
  - powsybl
vendors:
  - PowSyBl
products:
  - powsybl-computation-local (<= 7.2.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The library constructs shell command strings via concatenation and executes them (through bash -c for Unix, or cmd /c for Windows).
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The library constructs shell command strings via concatenation and executes them (through bash -c for Unix, or cmd /c for Windows).
    confidence_band: high
cves:
  - id: CVE-2026-55673
references:
  - https://github.com/advisories/GHSA-jqvf-j3ww-r8c7
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-55673
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade com.powsybl:powsybl-computation-local to 7.2.2 or later
      owner: IT Operations
      due: 48h
      evidence: Source advisory specifies version 7.2.2 as the fix for CVE-2026-55673
  mitigation_plan:
    - priority: immediate
      action: Apply input sanitization filter for command parameters
      owner: Application Security
      addresses: CVE-2026-55673
      evidence: Source advisory provides list of restricted characters for workarounds
---

PowSyBl Core, specifically the `powsybl-computation-local` package versions 7.2.1 and earlier, contains critical command injection vulnerabilities (CWE-78) and argument injection (CWE-88) flaws. The library constructs shell command strings using insecure concatenation methods before passing them to the underlying operating system shell (`bash -c` on Unix/Linux, `cmd /c` on Windows).

The vulnerability is exposed through public APIs in classes like `UnixLocalCommandExecutor`, `WindowsLocalCommandExecutor`, and `LocalComputationManager`, as well as several itools commands including `action-simulator` and `security-analysis`. Because the library does not properly sanitize input parameters or environment variables, an attacker providing input to these APIs can escape the intended command sequence and execute arbitrary shell instructions with the privileges of the JVM process. This poses a significant risk to downstream services, such as REST front-ends or multi-tenant grid analysis platforms that process external inputs.

## Impact

Successful exploitation allows an attacker to execute arbitrary shell commands with the privileges of the JVM user. This includes full system access, unauthorized file operations (read/write/execute), process spawning, and data exfiltration. The impact is elevated for services that expose these computation parameters to untrusted users, enabling remote code execution without the attacker needing to interact with the PowSyBl codebase directly.

## Recommendation

- Upgrade `com.powsybl:powsybl-computation-local` to version 7.2.2 or higher immediately to address CVE-2026-55673.
- If immediate patching is not feasible, implement strict input validation for all user-provided arguments in the application layer, forbidding shell metacharacters such as ';', '|', '&', '$', and others identified in the official advisory for Unix and Windows systems.
- Audit applications that integrate `powsybl-computation-local` to determine if they pass untrusted input to any of the vulnerable public methods, including `LocalComputationManager.execute()` or the `itools` command-line utilities.
