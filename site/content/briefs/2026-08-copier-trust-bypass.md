---
title: Copier Trust-Prefix Bypass via Path Traversal
slug: 2026-08-copier-trust-bypass
description: Copier versions 9.5.0 through 9.15.1 contain an authorization bypass vulnerability in the 'trust' configuration where insufficient path normalization allows attackers to execute arbitrary tasks by traversing out of trusted template prefixes.
date: "2026-08-19T22:34:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - supply-chain
vendors:
  - Copier
products:
  - copier (>= 9.5.0, <= 9.15.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malicious template's tasks / migrations / jinja_extensions then run without the --trust prompt — arbitrary command execution.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who hands you a project controls the URL that the trust check is applied to.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-9gmc-jqmh-3rvm
  - https://cwe.mitre.org/data/definitions/22.html
  - https://cwe.mitre.org/data/definitions/94.html
---

Copier versions 9.5.0 through 9.15.1 contain an authorization bypass vulnerability in the 'trust' configuration logic. When users define a 'trust' setting with a trailing slash, Copier interprets this as a trusted prefix. However, the application uses a raw 'str.startswith' check in 'copier/_settings.py' against the template URL without performing path normalization. 

Because the underlying mechanisms used to fetch the template (such as git or pathlib) normalize the URL and resolve dot-segments, an attacker can craft a template reference that textually begins with a trusted prefix but includes '..' to escape into an attacker-controlled directory or repository. This causes Copier to grant trust to a malicious template that it should have rejected. Consequently, the 'unsafe-feature' gate is bypassed, and the malicious template's 'tasks', 'migrations', or 'jinja_extensions' are executed without the required user prompt, leading to arbitrary command execution on the victim's machine. This is particularly dangerous during 'copier update' operations where the template source can be influenced by the project configuration.

## Attack Chain

1. The victim configures a trusted template prefix in the Copier settings (e.g., '/trusted/').
2. The attacker modifies a '.copier-answers.yml' file within a project or convinces the victim to update a project referencing a malicious template.
3. The attacker provides a template URL that starts with the trusted prefix but contains path traversal segments (e.g., '/trusted/../attacker/repo').
4. Copier's 'is_trusted_repository' function performs a raw string comparison, sees the trusted prefix, and grants trust.
5. Copier passes the URL to the underlying fetching mechanism (git or filesystem operations), which resolves the path to the attacker-controlled location.
6. Copier skips the 'unsafe-feature' check because it incorrectly believes the source is trusted.
7. Copier executes the tasks, migrations, or jinja_extensions defined in the malicious template.
8. Arbitrary commands execute on the victim's host with the privileges of the user running the Copier process.

## Impact

Successful exploitation allows for remote code execution on the user's workstation. This affects developers and automated systems utilizing Copier to manage project templates. If a user performs a 'copier update' on a compromised project, the attacker gains the ability to run arbitrary system commands, potentially leading to full account compromise or lateral movement within the developer's environment.

## Recommendation

* Upgrade to a patched version of Copier immediately (>= 9.15.2).
* Avoid configuring wide directory prefixes in the 'trust' setting if possible, and verify the integrity of all template sources.
* Audit project configuration files (specifically '.copier-answers.yml') for template URLs containing unusual path segments like '..' or attempts to escape defined trusted paths.
