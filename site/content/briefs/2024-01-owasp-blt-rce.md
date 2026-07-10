---
title: OWASP BLT RCE via Malicious Pull Request
slug: 2024-01-owasp-blt-rce
description: OWASP BLT versions before 2.1.1 are vulnerable to remote code execution via a malicious pull request that injects code into the CI environment through the 'regenerate-migrations' workflow.
date: "2024-01-02T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - owasp-blt
  - rce
  - github-actions
  - supply-chain
vendors:
  - OWASP
products:
  - OWASP BLT
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
cves:
  - id: CVE-2026-40316
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40316
rules:
  - title: Detect Suspicious models.py Modification in Pull Requests
    description: Detects pull requests that modify models.py with potentially malicious code
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - webserver
      - linux
  - title: Detect python manage.py makemigrations Execution in Github Actions
    description: Detects the execution of python manage.py makemigrations command within a Github Actions environment, which could indicate exploitation of CVE-2026-40316
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OWASP BLT, a QA testing and vulnerability disclosure platform, is susceptible to a critical remote code execution (RCE) vulnerability (CVE-2026-40316) in versions prior to 2.1.1. The vulnerability resides in the `.github/workflows/regenerate-migrations.yml` workflow. This workflow utilizes the `pull_request_target` trigger, granting it full `GITHUB_TOKEN` write permissions. An attacker can exploit this by submitting a malicious pull request containing a specially crafted `website/models.py` file. When a maintainer applies the `regenerate-migrations` label, the workflow copies files from the untrusted pull request, specifically the `website/models.py` file, into the trusted runner workspace using `git show`. Subsequently, the workflow executes `python manage.py makemigrations`, which imports Django model modules, including the attacker-controlled `website/models.py`. This import leads to the execution of any module-level Python code within the attacker's `models.py` file. This results in arbitrary code execution within the privileged CI environment, enabling access to `GITHUB_TOKEN` and repository secrets.

## Attack Chain

1.  An attacker creates a malicious fork of an OWASP BLT repository running a version prior to 2.1.1.
2.  The attacker crafts a `website/models.py` file containing malicious Python code designed for remote code execution, such as exfiltrating secrets or injecting a reverse shell.
3.  The attacker submits a pull request to the upstream OWASP BLT repository, including the malicious `website/models.py` file.
4.  A maintainer applies the `regenerate-migrations` label to the pull request, triggering the `.github/workflows/regenerate-migrations.yml` workflow.
5.  The `git show` command within the workflow copies the attacker-controlled `website/models.py` file from the pull request into the runner's workspace.
6.  The `python manage.py makemigrations` command is executed, which imports the Django model modules, including the malicious `website/models.py` file.
7.  The attacker's malicious Python code within `website/models.py` is executed in the privileged CI environment, granting access to `GITHUB_TOKEN` and repository secrets.
8.  The attacker leverages the compromised `GITHUB_TOKEN` to exfiltrate sensitive information, inject malicious code, or perform other unauthorized actions within the repository, potentially leading to a supply chain attack.

## Impact

Successful exploitation of CVE-2026-40316 allows an attacker to achieve remote code execution within the OWASP BLT CI environment. This can lead to the exfiltration of sensitive information, such as API keys and credentials, potentially compromising connected systems. The attacker can also modify the repository code, inject malicious code, or even take complete control of the repository. This poses a significant risk to the integrity and security of the OWASP BLT project and its users. Given that OWASP BLT is used for QA testing and vulnerability disclosure, a successful attack could undermine trust in the platform itself, impacting numerous other projects and organizations.

## Recommendation

*   Upgrade OWASP BLT to version 2.1.1 or later to patch CVE-2026-40316.
*   Implement controls to restrict the use of the `regenerate-migrations` label and require multi-factor authentication for maintainers.
*   Monitor GitHub Actions logs for suspicious activity, particularly related to the `regenerate-migrations` workflow and the execution of `python manage.py makemigrations`. Deploy the Sigma rules in this brief to your SIEM to detect suspicious activity.
*   Implement code review processes to carefully examine pull requests, especially those modifying `website/models.py` or other critical files.
