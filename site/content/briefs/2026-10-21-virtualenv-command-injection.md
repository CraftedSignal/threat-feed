---
brief_id: brief-2026-10-21-virtualenv-command-injection
event_id: brief-2026-10-21-virtualenv-command-injection
revision: 1
activity_at: "2026-10-21T17:06:20Z"
title: 'PyPA virtualenv: Zsh command injection in activate script (CVE-2026-113726)'
slug: 2026-10-21-virtualenv-command-injection
description: The virtualenv activation script for zsh is vulnerable to command injection via the environment prompt when PROMPT_SUBST is enabled, allowing arbitrary code execution upon prompt rendering.
date: "2026-10-21T17:06:20Z"
lastmod: "2026-10-21T17:06:35Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source confirmed vulnerability and fix
cpes:
  - cpe:2.3:a:pypa:virtualenv:*:*:*:*:*:*:*:*
tags:
  - command-injection
  - virtualenv
  - zsh
  - cve-2026-113726
  - code-injection
  - supply-chain
  - python
  - cve-2026-113776
vendors:
  - PyPA
products:
  - virtualenv (<= 21.14.3)
  - virtualenv (20.26.6-21.14.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: A name that contains $(...), backticks or ${...} then runs as commands in the user's shell, once per prompt.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: Sourcing that script runs touch PWNED.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.006
    technique_name: Python
    evidence: the reporter also showed Python code execution through activate.xsh and bin/activate_this.py
    confidence_band: high
cves:
  - id: CVE-2026-113726
    cvss: 7.8
    epss: 0.00234
    kev_status: "false"
  - id: CVE-2026-113776
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-5vjq-rrrf-7h2q
  - https://github.com/pypa/virtualenv/commit/5b915367da82bd024b2a0d28d2f98007034b4aa2
  - https://github.com/advisories/GHSA-8rjx-v5ww-45pp
  - https://github.com/pypa/virtualenv/commit/602b26623a724827ff171bf11fef4ad186d01f74
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade virtualenv to 21.14.4 on all development and CI/CD systems.
      owner: IT Operations
      due: 48h
      evidence: Fixed in 21.14.4.
  mitigation_plan:
    - priority: immediate
      action: Set VIRTUAL_ENV_DISABLE_PROMPT=1 in zsh profiles or CI/CD configuration files.
      owner: IT Operations
      addresses: CVE-2026-113726
      evidence: Set VIRTUAL_ENV_DISABLE_PROMPT=1 before you source activate.
updates:
  - at: "2026-10-21T17:06:35Z"
    level: L2
    summary: added coverage for virtualenv (20.26.6-21.14.1)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-8rjx-v5ww-45pp
---

The virtualenv `activate` script fails to properly sanitize the environment name when setting the `PS1` prompt variable for zsh. In environments where the `PROMPT_SUBST` option is enabled (a default in frameworks like oh-my-zsh), the shell performs parameter and command substitution on the prompt string. An attacker who can influence the environment name or prompt string - such as through directory naming or CI/CD job metadata - can inject shell metacharacters (e.g., `$(...)`, backticks) to execute arbitrary commands every time the prompt is rendered. This vulnerability affects virtualenv versions through 21.14.3.

## Impact

Successful exploitation allows arbitrary command execution with the privileges of the user running the zsh session. This can be triggered by sourcing a malicious virtualenv activation script, which may be delivered via cloned repositories, unpacked archives, or CI/CD pipelines that dynamically name virtual environments based on external inputs.

## Recommendation

* Update virtualenv to version 21.14.4 or later.
* For environments where immediate patching is not possible, set the environment variable `VIRTUAL_ENV_DISABLE_PROMPT=1` before sourcing any `activate` script.
* Disable `PROMPT_SUBST` in zsh configurations if not strictly required for shell functionality.
* Audit existing virtual environment directories for suspicious characters in their naming convention, particularly those sourced within automated build environments or CI/CD runners.
