---
title: GitHub Secret Scanning Disabled
slug: 2024-01-02-github-secret-scanning-disabled
description: Detection of disabled GitHub Secret Scanning on a repository, indicating potential defense evasion by attackers seeking to introduce and exploit hardcoded secrets.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - defense-evasion
  - github
vendors:
  - GitHub
products:
  - GitHub
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
  - https://trigger.dev/blog/shai-hulud-postmortem
  - https://posthog.com/blog/nov-24-shai-hulud-attack-post-mortem
rules:
  - title: GitHub Secret Scanning Disabled
    description: Detects when GitHub Secret Scanning is disabled for a repository.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
      - linux
  - title: GitHub Actions Workflow Modification for Secret Exposure
    description: Detects modifications to GitHub Actions workflow files that may indicate an attempt to expose secrets.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

This alert identifies instances where GitHub Secret Scanning has been disabled for a repository. Secret scanning is a security feature that automatically detects hardcoded secrets, such as API keys and credentials, within a repository's codebase. Adversaries may disable this feature to evade detection while introducing or exploiting such secrets. This action can precede the introduction of malicious code containing hardcoded credentials, potentially leading to unauthorized access and data exfiltration. This rule specifically applies to any GitHub repository where secret scanning can be enabled or disabled.

## Attack Chain

1.  The attacker gains administrative or bot access to a GitHub repository.
2.  The attacker disables GitHub Secret Scanning for the repository.
3.  The attacker commits and pushes code containing plaintext credentials (API keys, passwords, tokens) to the repository.
4.  The attacker modifies a GitHub Actions workflow file to expose the embedded credentials during CI jobs.
5.  The CI job executes, printing the exposed credentials in the logs or artifacts.
6.  The attacker extracts the exposed credentials from the CI job logs or artifacts.
7.  The attacker uses the stolen credentials to authenticate to external services (e.g., cloud accounts, third-party APIs).
8.  The attacker performs unauthorized actions on those external services, such as data exfiltration or resource provisioning.

## Impact

A successful attack could result in unauthorized access to sensitive data, systems, or services associated with the compromised credentials. The scope of impact depends on the permissions and access levels granted to the exposed secrets, and the attacker's ability to exploit those credentials. If Secret Scanning is disabled, an attacker has a higher chance of introducing such secrets.

## Recommendation

*   Deploy the Sigma rule `GitHub Secret Scanning Disabled` to your SIEM and tune for your environment to detect disabling events in near real-time.
*   Review commits, pull requests, and workflow file changes near the disable timestamp to detect added plaintext credentials.
*   Examine recent GitHub Actions runs, artifacts, and logs for secrets printed, unusual network egress, or jobs using elevated token scopes, and check for newly added or modified repo/org secrets.
*   Enforce org-wide policies requiring Secret Scanning and Push Protection for all repositories.
