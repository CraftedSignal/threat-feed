---
title: Wazuh GitHub Actions Shell Injection Vulnerability
slug: 2026-08-wazuh-shell-injection
description: A shell injection vulnerability in Wazuh workflows allows unauthenticated attackers to execute arbitrary commands and exfiltrate secrets via malicious pull requests containing crafted VERSION.json files.
date: "2026-08-01T13:50:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - ci-cd
  - code-injection
vendors:
  - Wazuh
products:
  - Wazuh
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: Attackers can inject shell metacharacters into environment variables that are directly interpolated into run steps, enabling command execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Wazuh workflows before 44bf114 contain a shell injection vulnerability in GitHub Actions that allows attackers to execute arbitrary commands.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: enabling command execution and exfiltration of secrets including GITHUB_TOKEN and AWS credentials on self-hosted runners.
    confidence_band: high
cves:
  - id: CVE-2026-67308
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67308
  - https://github.com/wazuh/wazuh/security/advisories/GHSA-95w2-gpvr-q4jh
  - https://www.vulncheck.com/advisories/wazuh-github-actions-shell-injection-via-fork-pull-request
---

Wazuh workflows prior to commit 44bf114 contain a critical shell injection vulnerability (CVE-2026-67308) in their GitHub Actions CI/CD pipeline. The flaw exists because the workflow improperly neutralizes shell metacharacters within the VERSION.json file before interpolating them into active shell command execution steps. By submitting a pull request containing a crafted VERSION.json file, an attacker can influence environment variables used by the runner. This results in arbitrary command execution on self-hosted runners. Because these runners often possess elevated privileges to interact with cloud infrastructure, successful exploitation enables the exfiltration of sensitive secrets, including the GITHUB_TOKEN and embedded AWS credentials. This vulnerability represents a significant risk to the integrity of the CI/CD pipeline and the underlying infrastructure managed by the affected Wazuh instances.

## Attack Chain

1. The attacker identifies a target repository using vulnerable Wazuh CI/CD workflows.
2. The attacker creates a fork of the Wazuh repository or initiates a pull request.
3. The attacker crafts a malicious VERSION.json file containing shell metacharacters (e.g., backticks, semicolon, or command redirection).
4. The attacker submits the pull request to the upstream repository.
5. The automated GitHub Actions CI/CD pipeline triggers upon the pull request submission.
6. The workflow process reads and interpolates the contents of the malicious VERSION.json file into a shell execution context.
7. The attacker-supplied commands execute with the privileges of the GitHub Action runner environment.
8. The injected code identifies and exfiltrates sensitive environment variables such as GITHUB_TOKEN or AWS credentials to an attacker-controlled server.

## Impact

Successful exploitation allows for complete compromise of the self-hosted runner environment. This permits unauthorized access to cloud-provider secrets, potential lateral movement into the build infrastructure, and the ability to inject malicious code into downstream software releases or internal tools, impacting the integrity of the Wazuh supply chain.

## Recommendation

1. Upgrade all Wazuh workflow configurations to the version identified by commit 44bf114 or later to remediate CVE-2026-67308.
2. Audit self-hosted runner logs for unusual process execution patterns immediately following pull request events.
3. Rotate all credentials and tokens that were potentially accessible to the GitHub Actions runner environment, specifically targeting AWS IAM keys and GITHUB_TOKEN values.
4. Restrict permissions for self-hosted runners and implement OIDC (OpenID Connect) for cloud provider authentication to reduce the blast radius of potential secret exfiltration.
