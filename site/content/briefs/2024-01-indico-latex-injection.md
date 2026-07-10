---
title: Indico LaTeX Injection Vulnerability (CVE-2026-33046)
slug: 2024-01-indico-latex-injection
description: A critical vulnerability in Indico versions prior to 3.3.12 allows specially-crafted LaTeX snippets to achieve local file read or arbitrary code execution due to insufficient sanitization of LaTeX input, impacting systems where server-side LaTeX rendering is enabled.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - CVE-2026-33046
  - indico
  - latex
  - code_execution
  - file_read
vendors:
  - Indico
products:
  - Indico
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33046
rules:
  - title: Detect Indico LaTeX Code Execution via Process Creation
    description: Detects potential code execution resulting from the Indico LaTeX injection vulnerability by monitoring for suspicious processes spawned by the LaTeX renderer (xelatex).
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Indico LaTeX Injection Attempts via Web Logs
    description: Detects potential Indico LaTeX injection attempts by monitoring web server logs for suspicious LaTeX syntax in request parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Indico, an event management system, is vulnerable to a critical flaw (CVE-2026-33046) affecting versions prior to 3.3.12. This vulnerability stems from insufficient sanitization of LaTeX input, allowing attackers to inject specially-crafted LaTeX snippets. By exploiting vulnerabilities in TeXLive and leveraging obscure LaTeX syntax to bypass Indico's LaTeX sanitizer, a malicious actor can potentially read local files or execute arbitrary code on the server. The vulnerability is triggered if server-side LaTeX rendering is enabled, indicated by the presence of `XELATEX_PATH` in the `indico.conf` file. This poses a significant risk to organizations utilizing Indico for event management, potentially leading to data breaches or complete system compromise. Defenders must take immediate action to mitigate this risk by updating Indico or disabling LaTeX rendering.

## Attack Chain

1. An attacker identifies an Indico instance running a version prior to 3.3.12 with server-side LaTeX rendering enabled (XELATEX_PATH configured).
2. The attacker crafts a malicious LaTeX snippet designed to either read local files or execute arbitrary code. This snippet exploits vulnerabilities in TeXLive and utilizes obscure LaTeX syntax to bypass Indico's built-in sanitization mechanisms.
3. The attacker injects the malicious LaTeX snippet into a field that is processed by the LaTeX rendering engine. This could be a presentation abstract, a comment, or any other user-controlled input field.
4. Indico's server-side LaTeX rendering engine processes the injected snippet using xelatex.
5. Due to the insufficient sanitization, the malicious LaTeX code executes. If designed for file access, the attacker can read sensitive files accessible to the Indico user. If designed for code execution, the attacker gains shell access under the Indico user's privileges.
6. If the attacker successfully gains code execution, they may establish persistence by creating cron jobs or modifying system files.
7. The attacker may attempt to escalate privileges within the system to gain root access.
8. The attacker can then exfiltrate sensitive data, deploy ransomware, or further compromise the Indico system and the network it resides on.

## Impact

Successful exploitation of this vulnerability allows attackers to read arbitrary local files or execute arbitrary code on the Indico server. This can lead to the disclosure of sensitive information, such as database credentials, user data, and internal documents. In the worst-case scenario, an attacker can gain complete control of the Indico server, potentially impacting hundreds or thousands of users and events managed by the platform. The affected sectors are broad, including academic institutions, research organizations, and conference organizers who rely on Indico for event management.

## Recommendation

*   Immediately upgrade Indico to version 3.3.12 or later to patch CVE-2026-33046.
*   Enable the containerized LaTeX renderer using `podman`, as suggested in the advisory, to isolate the rendering process and mitigate the impact of successful exploitation.
*   If upgrading or enabling containerization is not immediately feasible, remove the `XELATEX_PATH` setting from `indico.conf` (or comment it out or set it to `None`) and restart the `indico-uwsgi` and `indico-celery` services to disable LaTeX functionality. This will prevent the exploitation of the vulnerability.
*   Deploy the Sigma rule "Detect Indico LaTeX Code Execution via Process Creation" to detect potential exploitation attempts by monitoring for suspicious processes spawned by the LaTeX renderer.
*   Monitor web server logs for requests containing suspicious LaTeX syntax in request parameters that are likely to be processed by the LaTeX rendering engine, using the Sigma rule "Detect Indico LaTeX Injection Attempts via Web Logs".
