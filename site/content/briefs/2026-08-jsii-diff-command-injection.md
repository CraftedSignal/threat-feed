---
title: Command Injection in jsii-diff via NPM Package Specifiers
slug: 2026-08-jsii-diff-command-injection
description: The jsii-diff tool fails to sanitize inputs provided with an 'npm:' prefix, allowing unauthenticated attackers to execute arbitrary shell commands via crafted package specifiers.
date: "2026-08-07T21:31:08Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Amazon
products:
  - jsii-diff (< 1.131.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: By injecting a ; into the package-specifier part of that command, jsii-diff can be tricked into running shell commands.
    confidence_band: high
cves:
  - id: CVE-2026-15895
    cvss: 7.8
    epss: 0.0063
references:
  - https://github.com/advisories/GHSA-wcx4-wpfv-mc5c
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-15895
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - DevOps
  immediate_actions:
    - action: Upgrade jsii-diff to 1.131.0 in all build environments
      owner: DevOps
      due: 48h
      evidence: This issue has been addressed in jsii-diff version 1.131.0.
  mitigation_plan:
    - priority: immediate
      action: Audit CI/CD pipeline inputs for user-controlled command arguments
      owner: DevOps
      addresses: CVE-2026-15895
      evidence: If you are unable to update, make sure only trusted actors can control the arguments passed to jsii-diff.
---

The jsii-diff utility, an API compatibility comparison tool used within development pipelines, contains a command injection vulnerability tracked as CVE-2026-15895. The flaw exists in the tool's handling of command-line arguments that begin with the "npm:" prefix, which triggers an automated package retrieval process. 

The application improperly sanitizes the package specifier argument, allowing an attacker to inject shell metacharacters such as semicolons directly into the command string passed to the underlying system shell. This vulnerability allows an attacker to execute arbitrary commands with the same security context and permissions as the user or service account executing jsii-diff. Because this tool is commonly integrated into automated CI/CD pipelines, this vulnerability poses a significant risk to the integrity of build environments. This issue was addressed in version 1.131.0, and defenders are urged to audit pipeline configurations to ensure that input passed to this tool cannot be manipulated by untrusted sources.

## Impact

Successful exploitation allows local command execution, potentially leading to unauthorized data exfiltration, modification of pipeline artifacts, or persistence within the development environment. The risk is highest in CI/CD environments where user-supplied inputs may be passed to the jsii-diff utility without sufficient validation or containment.

## Recommendation

* Upgrade the jsii-diff package to version 1.131.0 or higher across all development, build, and CI/CD environments.
* Audit all CI/CD pipelines and automation scripts to identify instances where user-supplied data is concatenated into command-line arguments for jsii-diff.
* If upgrading is not immediately possible, implement strict input validation to ensure that any argument beginning with "npm:" adheres to expected alphanumeric formats and contains no shell metacharacters such as ';', '|', '&', or '$'.
