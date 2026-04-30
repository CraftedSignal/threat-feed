---
title: GitHub Push Protection Bypass Detection
slug: 2024-04-github-push-protection-bypass
description: Detection of a GitHub user bypassing push protection, potentially leading to the exposure of secrets.
date: "2024-04-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-impairment
  - t1685
  - github
vendors:
  - Github
products:
  - Github
references:
  - https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/push-protection-for-repositories-and-organizations
  - https://thehackernews.com/2024/03/github-rolls-out-default-secret.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_push_protection_bypass_detected.yml
rules:
  - title: Github Push Protection Bypass Detected
    description: Detects when a user bypasses the push protection on a secret detected by secret scanning.
    platform: sigma
    severity: low
    tactics:
      - defense-impairment
    data_sources:
      - github
      - audit
  - title: Github Admin Forced Push
    description: Detects when an administrator force pushes to a repository, potentially bypassing protections
    platform: sigma
    severity: informational
    tactics:
      - defense-impairment
    data_sources:
      - github
      - audit
rules_count: 2
---

This alert detects when a GitHub user bypasses the push protection mechanism designed to prevent secrets from being committed to a repository. GitHub's push protection, part of its secret scanning feature, is intended to block commits containing sensitive information like API keys or credentials.  A bypass indicates a deliberate attempt to circumvent this security measure. Successful bypass can lead to exposure of secrets, increasing the risk of unauthorized access and data breaches. The activity is logged within GitHub's audit logs, provided that the audit log streaming feature is enabled.

## Attack Chain

1. Developer attempts to commit code containing a secret to a GitHub repository.
2. GitHub's push protection mechanism detects the secret and blocks the push.
3. The developer intentionally bypasses the push protection, potentially using allowed administrative activities to circumvent the block.
4. The code, including the secret, is successfully pushed to the repository.
5. The secret becomes exposed within the repository's history.
6. Unauthorized actors may discover the exposed secret by scanning the repository.
7. Unauthorized actors may use the exposed secret to gain unauthorized access to systems or data.

## Impact

A successful bypass of GitHub push protection can lead to secrets being exposed in a repository. This exposure can lead to unauthorized access to sensitive systems or data. The severity of the impact depends on the scope of access granted by the exposed secret, and the visibility of the repository.

## Recommendation

*   Enable audit log streaming in GitHub to ensure relevant events are captured.
*   Deploy the Sigma rule "Github Push Protection Bypass Detected" to your SIEM and tune for your environment using GitHub audit logs.
*   Investigate any detected bypass events to determine the context and impact of the bypassed secret.
