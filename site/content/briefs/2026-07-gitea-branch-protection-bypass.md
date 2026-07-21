---
title: Gitea Branch Protection Bypass via Pull Request Retargeting
slug: 2026-07-gitea-branch-protection-bypass
description: An attacker with write access to a Gitea repository can bypass branch protection rules by exploiting a logic flaw, obtaining an 'official' approval on a pull request (PR) targeting an unprotected branch, then retargeting the PR to a protected branch, preserving the stale approval and leading to unauthorized code merges and privilege escalation.
date: "2026-07-21T20:15:57Z"
lastmod: "2026-07-21T21:07:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - branch-protection-bypass
  - code-repository
  - privilege-escalation
  - gitea
  - persistence
  - web-application
  - vulnerability
  - defense-evasion
  - network
  - credential-theft
  - mitm
  - certificate-validation-bypass
  - cve
  - code-hosting
  - supply-chain-attack
  - data-exfiltration
vendors:
  - Gitea
products:
  - Gitea (< 1.27.0)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: An attacker with write access to a Gitea repository can bypass branch protection rules by exploiting a logic flaw, obtaining an 'official' approval on a pull request (PR) targeting an unprotected branch, then retargeting the PR to a protected branch, preserving the stale approval and leading to unauthorized code merges and privilege escalation.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A user with write-but-not-admin access can effectively nullify the admin-configured approval requirements
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: As a result, the attacker's active session is never invalidated, and the attacker maintains persistent, indefinite access to the victim's account, entirely defeating the purpose of the split-token security design.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: An attacker with a restricted token (e.g. write:user from a leaked CI secret) can therefore create a fully-privileged all-scoped token without knowing the account password.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: An attacker with on-path position on that internal segment can MITM the connection and capture the static high-privilege INTERNAL_TOKEN
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: No entry written to the repository's audit/activity log; No webhook event fired; No org-level notification to owners; No email alert to watchers; The database update uses `UpdateRepositoryColsNoAutoTime`, which also suppresses the `updated_at` timestamp change
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: 'Data exfiltration: Private source code, CI/CD secrets in plain-text files, environment configs become publicly cloneable for the window the repo is public'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w5pg-649r-p6gg
  - https://github.com/advisories/GHSA-rgv6-xp99-6mgj
  - https://github.com/go-gitea/gitea/blob/689ace1ce28fd74244b8aa335d9928cdbf6b22f9/services/auth/auth_token.go#L33-L64
  - https://github.com/go-gitea/gitea/blob/689ace1ce28fd74244b8aa335d9928cdbf6b22f9/services/auth/auth_token.go#L21
  - https://github.com/advisories/GHSA-683j-3ff6-hh2x
  - https://github.com/advisories/GHSA-94v3-77j7-vm48
  - https://github.com/advisories/GHSA-8p9h-49rc-qgxj
rules:
  - title: Detects CVE-2026-58439 Exploitation Attempt - Gitea Pull Request Retargeting
    description: Detects CVE-2026-58439 exploitation - Gitea API PATCH requests targeting pull requests, which is a key step in the branch protection bypass. This rule monitors for attempts to retarget a PR's base branch.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1078.003
      - T1562.001
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-21T20:21:48Z"
    level: L2
    summary: 'merged source coverage: Gitea Remember-Me Token Theft Not Invalidating Attacker Session'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-rgv6-xp99-6mgj
  - at: "2026-07-21T20:26:02Z"
    level: L2
    summary: 'merged source coverage: Gitea Privilege Escalation via Access Token Scope Escalation'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-683j-3ff6-hh2x
  - at: "2026-07-21T20:48:29Z"
    level: L2
    summary: 'merged source coverage: Gitea Internal API InsecureSkipVerify Vulnerability (CVE-2026-54481)'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-94v3-77j7-vm48
  - at: "2026-07-21T21:07:18Z"
    level: L2
    summary: 'merged source coverage: Gitea Repository Visibility Manipulation via Git Push Options'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-8p9h-49rc-qgxj
---

A critical vulnerability, CVE-2026-58439, affects Gitea versions prior to 1.27.0, enabling attackers with write access to a repository to bypass branch protection rules. The flaw stems from Gitea's failure to re-evaluate the `official` flag on existing pull request reviews when a PR's target branch is changed. This allows an attacker to first create a pull request (PR) targeting an unprotected branch, obtain a seemingly legitimate "official: true" approval from any non-whitelisted account, and then retarget the PR to a protected branch (e.g., `master`). Because the stale "official: true" flag is preserved, it satisfies the protected branch's required approval count, enabling the attacker to merge malicious code without true maintainer oversight. This bypass effectively escalates privileges and undermines secure code collaboration workflows.

## Attack Chain

1. An attacker, with write access to a Gitea repository but not in the protected branch's approval whitelist, creates a temporary unprotected branch from the main branch using the Gitea API.
2. The attacker pushes a malicious commit to a feature branch derived from the main branch.
3. The attacker creates a new pull request (PR) targeting the *unprotected* temporary branch (`tmp-unprotected`) with their malicious feature branch using the Gitea API.
4. An accomplice (any non-admin, non-whitelisted user) approves this PR, which Gitea records as `official: true` because the target branch is unprotected.
5. The attacker then retargets the PR to the *protected* main branch (`master` in the example) by sending a `PATCH` request to the PR endpoint via the Gitea API.
6. Gitea's backend fails to re-evaluate or dismiss the existing reviews, preserving the stale `official: true` flag from the previous approval.
7. The attacker initiates a merge of the PR into the protected main branch by sending a `POST` request to the PR merge endpoint. The merge succeeds because the preserved `official: true` approval satisfies the protected branch's requirements, allowing unauthorized code changes.

## Impact

Successful exploitation of CVE-2026-58439 leads to a complete bypass of Gitea's branch protection mechanisms. This allows any user with write access to a repository to merge arbitrary code into protected branches, even if they are not authorized by the designated approval whitelist. This constitutes a significant privilege escalation, as it nullifies admin-configured security controls and enables unauthorized code injection into critical production or development branches. The direct consequence is the introduction of malicious or unapproved code, potentially leading to supply chain attacks, system compromise, or data breaches within the affected environment.

## Recommendation

* **Upgrade Gitea immediately** to version 1.27.0 or later to patch CVE-2026-58439.
* **Deploy the Sigma rule** "Detects CVE-2026-58439 Exploitation Attempt - Gitea Pull Request Retargeting" to your SIEM to alert on attempts to retarget pull requests via the API.
* **Review Gitea webserver logs** for `PATCH` requests to `/api/v1/repos/*/pulls/*` followed by `POST` requests to `/api/v1/repos/*/pulls/*/merge` from users not typically associated with such administrative actions, especially for protected branches.
