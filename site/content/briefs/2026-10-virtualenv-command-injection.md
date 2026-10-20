---
brief_id: brief-2026-10-20-virtualenv-command-injection
event_id: brief-2026-10-20-virtualenv-command-injection
revision: 1
activity_at: "2026-10-20T21:56:26Z"
title: 'Python virtualenv: POSIX console script command injection (CVE-2026-113722)'
slug: 2026-10-virtualenv-command-injection
description: A command injection vulnerability in virtualenv prior to 21.14.9 allows arbitrary code execution via malformed interpreter paths when generating POSIX console scripts.
date: "2026-10-20T21:56:26Z"
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
  validation_status: Source verified against NVD data
cpes:
  - cpe:2.3:a:pypa:virtualenv:*:*:*:*:*:python:*:*
tags:
  - vulnerability
  - python
  - command-injection
vendors:
  - Python Packaging Authority
products:
  - virtualenv (< 21.14.9)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: When the path contains a space or produces a shebang longer than 127 bytes, distlib emits a /bin/sh wrapper whose double-quoted interpreter path still expands command substitutions and backticks.
    confidence_band: high
cves:
  - id: CVE-2026-113722
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113722
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Developer Productivity
  immediate_actions:
    - action: Upgrade virtualenv to 21.14.9 and regenerate all environment launchers
      owner: IT Operations
      due: 48h
      evidence: Vulnerability remediation requirement provided in advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade virtualenv to version 21.14.9
      owner: IT Operations
      addresses: CVE-2026-113722
      evidence: Remediation provided by vendor
---

The virtualenv tool, used for creating isolated Python environments, contains a command injection vulnerability (CVE-2026-113722) resulting from improper quoting of interpreter paths. When virtualenv or pip utilizes distlib to generate POSIX console scripts, specific conditions involving interpreter path strings - specifically those containing spaces or triggering shebangs exceeding 127 bytes - cause distlib to generate a /bin/sh wrapper. This wrapper fails to sufficiently quote the interpreter path, permitting the evaluation of command substitutions and backticks contained within the path.

An attacker who can control the destination path of a virtual environment creation process can force the execution of arbitrary commands under the privileges of the user who subsequently runs the generated launcher. This vulnerability affects systems utilizing virtualenv versions prior to 21.14.9. Notably, simply upgrading the virtualenv package does not remediate existing vulnerable launchers; they must be explicitly regenerated. Furthermore, independent pip operations may reintroduce the flaw due to vendored versions of distlib, requiring consistent environment management practices.

## Impact

Successful exploitation allows local command injection when a user executes a generated launcher within a maliciously constructed or influenced environment path. This primarily impacts developers and automated build systems that rely on virtualenv to manage project dependencies on Linux and macOS environments. The scope includes any workflow where an attacker can influence the filesystem structure or environment creation parameters.

## Recommendation

* Upgrade virtualenv to version 21.14.9 or later immediately to patch the script generation logic.
* Regenerate all existing virtual environments and associated launchers after applying the patch, as upgrading the base package does not automatically remediate legacy launchers.
* Audit build pipelines and automation scripts that define environment paths to ensure they do not incorporate untrusted or externally influenced input strings that could contain spaces or shell metacharacters.
