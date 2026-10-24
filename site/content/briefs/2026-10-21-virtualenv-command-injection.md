---
brief_id: brief-2026-10-21-virtualenv-command-injection
event_id: brief-2026-10-21-virtualenv-command-injection
revision: 3
activity_at: "2026-10-24T21:58:09Z"
revision_history:
  - revision: 2
    at: "2026-10-24T03:46:57Z"
    checksum: sha256:a9193646b5fbba69e5bc1ece79720a3c27d802aebf4e2f56e21c52486370e00d
    summary: added coverage for virtualenv (< 21.14.9)
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-6w3r-xr62-4xcp
  - revision: 3
    at: "2026-10-24T21:58:09Z"
    checksum: sha256:6c5708644df9c8f1bcdabcf7ea6b582b9892f3250a66db0235e061e3c899f1e4
    summary: added coverage for virtualenv (>= 21.14.9, < 21.14.13)
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-cx6f-vjhg-g3cc
title: 'PyPA virtualenv: Zsh command injection in activate script (CVE-2026-113726)'
slug: 2026-10-21-virtualenv-command-injection
description: The virtualenv activation script for zsh is vulnerable to command injection via the environment prompt when PROMPT_SUBST is enabled, allowing arbitrary code execution upon prompt rendering.
date: "2026-10-21T17:06:20Z"
lastmod: "2026-10-24T21:57:18Z"
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
  - virtualenv (< 21.14.9)
  - virtualenv (>= 21.14.9, < 21.14.13)
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
  - id: CVE-2026-113723
    epss: 0.00142
    kev_status: "false"
  - id: CVE-2026-115586
    epss: 0.00189
    kev_status: "false"
  - id: CVE-2026-113776
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-5vjq-rrrf-7h2q
  - https://github.com/pypa/virtualenv/commit/5b915367da82bd024b2a0d28d2f98007034b4aa2
  - https://github.com/advisories/GHSA-8rjx-v5ww-45pp
  - https://github.com/pypa/virtualenv/commit/602b26623a724827ff171bf11fef4ad186d01f74
  - https://github.com/advisories/GHSA-6w3r-xr62-4xcp
  - https://github.com/pypa/virtualenv/pull/3418
  - https://github.com/advisories/GHSA-cx6f-vjhg-g3cc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115586
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
    - Security Engineering
    - Detection Engineering
  immediate_actions:
    - action: Upgrade virtualenv to 21.14.4 on all development and CI/CD systems.
      owner: IT Operations
      due: 48h
      evidence: Fixed in 21.14.4.
    - action: Upgrade virtualenv to 21.14.9 or later across all developer workstations and CI/CD environments
      owner: IT Operations
      due: 48h
      evidence: Fixed in 21.14.9.
    - action: Upgrade virtualenv to 21.14.13 across all developer workstations and CI/CD pipelines
      owner: IT Operations
      due: 48h
      evidence: Source advisory confirms patch in 21.14.13
  hunt_leads:
    - lead: Audit shell history or process lineage for 'virtualenv' command lines containing shell syntax in the --prompt argument
      technique_id: T1059.004
      data_needed:
        - Process command line logging
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker controls prompt or destination data passed as a virtualenv argument.
    - lead: Search bash history or shell configurations for 'source bin/activate' or 'virtualenv' commands utilizing the '--prompt' flag
      technique_id: T1059.004
      data_needed:
        - Bash history logs
        - Shell process execution telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker-controlled input arrives via the --prompt command line argument.
  mitigation_plan:
    - priority: immediate
      action: Set VIRTUAL_ENV_DISABLE_PROMPT=1 in zsh profiles or CI/CD configuration files.
      owner: IT Operations
      addresses: CVE-2026-113726
      evidence: Set VIRTUAL_ENV_DISABLE_PROMPT=1 before you source activate.
    - priority: immediate
      action: Set VIRTUAL_ENV_DISABLE_PROMPT=1 globally for users relying on legacy virtualenv versions
      owner: Security Engineering
      addresses: CVE-2026-113723
      evidence: On older releases, disable the environment prompt with VIRTUAL_ENV_DISABLE_PROMPT=1.
    - priority: immediate
      action: Set VIRTUAL_ENV_DISABLE_PROMPT=1 globally or in shell profiles for users working with virtualenv
      owner: IT Operations
      addresses: CVE-2026-115586
      evidence: Known mitigation listed in advisory
updates:
  - at: "2026-10-21T17:06:35Z"
    level: L2
    summary: added coverage for virtualenv (20.26.6-21.14.1)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-8rjx-v5ww-45pp
  - at: "2026-10-24T03:45:45Z"
    level: L2
    summary: added coverage for virtualenv (< 21.14.9)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-6w3r-xr62-4xcp
  - at: "2026-10-24T21:57:18Z"
    level: L2
    summary: added coverage for virtualenv (>= 21.14.9, < 21.14.13)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-cx6f-vjhg-g3cc
---

The virtualenv `activate` script fails to properly sanitize the environment name when setting the `PS1` prompt variable for zsh. In environments where the `PROMPT_SUBST` option is enabled (a default in frameworks like oh-my-zsh), the shell performs parameter and command substitution on the prompt string. An attacker who can influence the environment name or prompt string - such as through directory naming or CI/CD job metadata - can inject shell metacharacters (e.g., `$(...)`, backticks) to execute arbitrary commands every time the prompt is rendered. This vulnerability affects virtualenv versions through 21.14.3.

## Impact

Successful exploitation allows arbitrary command execution with the privileges of the user running the zsh session. This can be triggered by sourcing a malicious virtualenv activation script, which may be delivered via cloned repositories, unpacked archives, or CI/CD pipelines that dynamically name virtual environments based on external inputs.

## Recommendation

* Update virtualenv to version 21.14.4 or later.
* For environments where immediate patching is not possible, set the environment variable `VIRTUAL_ENV_DISABLE_PROMPT=1` before sourcing any `activate` script.
* Disable `PROMPT_SUBST` in zsh configurations if not strictly required for shell functionality.
* Audit existing virtual environment directories for suspicious characters in their naming convention, particularly those sourced within automated build environments or CI/CD runners.
