---
title: Command Injection in PraisonAI Deployment API and Docker Generation
slug: 2026-10-praisonai-rce
description: PraisonAI versions 4.6.77 and earlier are vulnerable to arbitrary code execution via command injection in the deploy/api.py and deploy/docker.py modules due to unsanitized f-string interpolation.
date: "2026-10-07T16:57:36Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - PraisonAI
products:
  - PraisonAI (<= 4.6.77)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: 'The generated code is then executed (line 190): subprocess.Popen([''python'', server_file])'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-g6j7-pffp-8whg
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - DevOps
  immediate_actions:
    - action: Upgrade PraisonAI to version > 4.6.77
      owner: DevOps
      due: 24h
      evidence: CVE-2026-62176 affects <= 4.6.77
  mitigation_plan:
    - priority: immediate
      action: Upgrade PraisonAI to version > 4.6.77
      owner: DevOps
      addresses: CVE-2026-62176
      evidence: Source advisory recommends remediation
---

PraisonAI, a framework for AI agent orchestration, contains a critical security vulnerability (CVE-2026-62176) allowing for arbitrary code execution. The vulnerability exists within the `deploy/api.py` and `deploy/docker.py` modules. The application generates Python server code and Dockerfiles using f-string interpolation to insert the `agents_file` parameter directly into template strings without validation or sanitization.

An attacker who can influence the `agents_file` parameter - via CLI arguments, malicious configuration files, or upstream API input - can break out of the string literal context to inject arbitrary Python code. This injected code is subsequently executed when the generated Python script is invoked via `subprocess.Popen()` or when the Docker build process is initiated. The impact includes full command execution on the host machine running the deployment or build process, posing a significant risk to CI/CD pipelines and local development environments. This affects all versions up to and including 4.6.77.

## Attack Chain

1. The attacker identifies a target PraisonAI instance or build pipeline that consumes an untrusted `agents_file` parameter.
2. The attacker crafts a malicious `agents_file` string containing a payload designed to close the existing f-string and inject Python commands (e.g., `"); import os; os.system("id"); #`).
3. The attacker triggers the deployment process (e.g., via a CLI command, API request, or by submitting a malicious repository configuration).
4. PraisonAI's `deploy/api.py` or `deploy/docker.py` script reads the malicious input.
5. The vulnerability in the module interpolates the payload into a string template, resulting in a malformed Python script containing the attacker's commands.
6. The `subprocess.Popen()` function is called to execute the generated server file.
7. The operating system executes the Python script, triggering the injected shell commands with the privileges of the PraisonAI process.

## Impact

Successful exploitation allows for arbitrary code execution on the underlying host system. This could lead to full system compromise, exfiltration of credentials or sensitive data, and persistent access within a build environment if the target is an automated CI/CD pipeline.

## Recommendation

1. Upgrade PraisonAI to a version later than 4.6.77 immediately.
2. Implement input validation for any user-provided path or file parameters used in deployment or configuration scripts.
3. Audit CI/CD pipelines for configurations that allow external input to influence the `agents_file` parameter in PraisonAI tasks.
