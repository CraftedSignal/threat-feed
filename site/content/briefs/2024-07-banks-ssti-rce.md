---
title: banks Library Vulnerable to Server-Side Template Injection Leading to Remote Code Execution
slug: 2024-07-banks-ssti-rce
description: banks version 2.4.1 and earlier is vulnerable to Server-Side Template Injection (SSTI) due to the use of an unsandboxed Jinja2 environment, allowing attackers to achieve Remote Code Execution (RCE) by injecting malicious code through user-supplied prompt templates.
date: "2024-07-03T17:21:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssti
  - rce
  - jinja2
vendors:
  - masci
products:
  - banks (<= 2.4.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2024-41950
    cvss: 7.5
    epss: 0.03008
  - id: CVE-2025-25362
    cvss: 9.8
    epss: 0.00049
references:
  - https://github.com/advisories/GHSA-gphh-9q3h-jgpp
  - https://github.com/masci/banks/pull/74
rules:
  - title: Detect banks SSTI via Jinja2 Template Injection
    description: Detects potential Server-Side Template Injection (SSTI) attacks targeting the `banks` library by identifying suspicious Jinja2 syntax in HTTP requests to web applications.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect banks SSTI - File Write Attempt via Jinja2
    description: Detects attempts to write files via Jinja2 SSTI in web server logs, potentially indicating exploitation of the banks library.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The `banks` library, versions 2.4.1 and earlier, is susceptible to a critical Server-Side Template Injection (SSTI) vulnerability (CVE-2026-44209) due to its utilization of an unsandboxed Jinja2 environment. This flaw enables attackers to inject and execute arbitrary code on the host system by exploiting applications that pass user-supplied strings as the template argument to the `Prompt()` function. The vulnerability arises because the `jinja2.Environment()` is initialized without proper sandboxing, allowing access to dangerous Python built-ins. This vulnerability impacts any application that relies on `banks` and allows users to supply prompt templates, potentially leading to full system compromise.

## Attack Chain

1. An attacker identifies an application using `banks <= 2.4.1` that accepts user-controlled input for prompt templates.
2. The attacker crafts a malicious payload containing Jinja2 template code that leverages Python built-in functions for OS command execution (e.g., using `self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()`).
3. The attacker submits the malicious payload through a user-supplied input field, API endpoint, or configuration file that is then passed to the `Prompt()` function.
4. The `Prompt()` function processes the user-supplied string through the unsandboxed Jinja2 environment.
5. The Jinja2 template engine executes the embedded Python code within the malicious payload.
6. The `os.popen()` function executes the attacker-specified command on the host operating system.
7. The output of the command is captured and potentially returned as part of the rendered template.
8. The attacker gains arbitrary code execution on the server, enabling data exfiltration, system compromise, or further malicious activities.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary commands on the host system, potentially leading to full system compromise. Applications that allow users to supply or customize prompt templates are at significant risk. The impact includes data exfiltration, unauthorized access to sensitive information, and the potential for deploying ransomware or other malware. Similar vulnerabilities (CVE-2024-41950, CVE-2025-25362) in other libraries highlight the severity of this issue.

## Recommendation

*   Upgrade the `banks` library to version 2.4.2 or later, which implements a sandboxed Jinja2 environment to mitigate SSTI risks.
*   Implement input validation and sanitization on all user-supplied prompt templates to prevent the injection of malicious code.
*   Deploy the Sigma rule "Detect banks SSTI via Jinja2 Template Injection" to identify potential exploitation attempts in web server logs by monitoring for requests containing suspicious Jinja2 syntax.
*   Review applications using the `banks` library to identify and remediate any instances where user-controlled input is directly passed to the `Prompt()` function without proper sanitization.
