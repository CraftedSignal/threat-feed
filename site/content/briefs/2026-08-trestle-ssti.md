---
title: Trestle Server-Side Template Injection via Custom Jinja2 Extensions
slug: 2026-08-trestle-ssti
description: The Trestle command-line tool is vulnerable to Server-Side Template Injection (SSTI) due to the unsafe re-evaluation of untrusted Markdown content as Jinja2 template code.
date: "2026-08-28T21:19:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssti
  - rce
  - python
  - jinja2
vendors:
  - IBM
products:
  - trestle
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Because jinja2.Environment is used, injected expressions can traverse Python object chains to achieve arbitrary command execution via os.system or subprocess.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-jw39-3688-r4rx
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Restrict write access to Trestle workspace directories to mitigate unauthorized file injection.
      owner: IT Operations
      due: 24h
      evidence: 'Source workaround #4'
  mitigation_plan:
    - priority: immediate
      action: Modify trestle/core/jinja/tags.py to remove recursive Parser.parse() calls and adopt SandboxedEnvironment.
      owner: Development
      addresses: SSTI vulnerability in MDCleanInclude and MDSectionInclude
      evidence: Source fix recommendation
---

Trestle contains multiple Server-Side Template Injection (SSTI) vulnerabilities within its Jinja2 rendering pipeline. The application processes Markdown files and other data sources using custom Jinja2 extensions (`MDCleanInclude` and `MDSectionInclude`). These extensions improperly treat untrusted content as Jinja2 template source code by passing it directly to the `jinja2.Parser` object without adequate sanitization or sandboxing. Because the environment utilizes a standard `jinja2.Environment` rather than a `SandboxedEnvironment`, attackers can inject malicious Jinja2 expressions, such as object traversal payloads (e.g., `__class__.__mro__`, `__globals__`), to achieve arbitrary command execution via Python's `os.system` or `subprocess` modules. This pattern exists within `trestle/core/jinja/tags.py` and is triggered whenever a user-provided or workspace-modified Markdown file is processed by the Trestle authoring commands.

## Attack Chain

1. Attacker places a malicious `.md` file containing a Jinja2 payload (e.g., `{{ ... os.system(...) }}`) into the Trestle workspace.
2. Attacker executes the `trestle author jinja` CLI command, targeting a legitimate template that utilizes the vulnerable `{% md_clean_include %}` or `{% mdsection_include %}` tags.
3. The Trestle engine loads the malicious file from the filesystem via `FileSystemLoader`.
4. The `MDCleanInclude` or `MDSectionInclude` tag handler processes the file content, extracting the Markdown body without sanitization.
5. The extracted content is passed as raw string input to the `Parser` constructor in `trestle/core/jinja/tags.py`.
6. The `Parser.parse()` method triggers the evaluation of the injected Jinja2 syntax within the template context.
7. The injected Python payload executes with the privileges of the Trestle process, leading to full Remote Code Execution (RCE) or sensitive data exfiltration.

## Impact

Successful exploitation allows for arbitrary code execution on the system running the Trestle command. If used in automated CI/CD pipelines, this can result in the compromise of build environments, leakage of environment variables (e.g., API keys, AWS credentials), or lateral movement within the infrastructure.

## Recommendation

1. Immediately restrict write access to all Trestle workspace directories to trusted users to prevent the introduction of malicious Markdown files.
2. Patch the application code by modifying `trestle/core/jinja/tags.py` to stop re-parsing Markdown content via `Parser.parse()`, replacing it with `nodes.TemplateData` as suggested by the security advisory.
3. Transition from `jinja2.Environment` to `jinja2.sandbox.SandboxedEnvironment` in `trestle/core/commands/author/jinja.py` to restrict access to sensitive Python object attributes.
4. Implement a pre-commit hook or CI scanning gate to audit all workspace files for Jinja2 syntax patterns and dangerous Python method calls (e.g., `__globals__`, `os.system`, `subprocess`).
