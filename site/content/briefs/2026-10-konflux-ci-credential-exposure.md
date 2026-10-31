---
brief_id: brief-2026-10-31-konflux-ci-credential-exposure
event_id: brief-2026-10-31-konflux-ci-credential-exposure
revision: 1
activity_at: "2026-10-31T09:55:50Z"
title: 'Konflux CI: Plaintext GitHub access token exposure (CVE-2026-114217)'
slug: 2026-10-konflux-ci-credential-exposure
description: A vulnerability in konflux-ci allows local attackers on build runners to retrieve sensitive GitHub access tokens stored in plaintext by CI automation scripts.
date: "2026-10-31T09:55:50Z"
lastmod: "2026-10-31T09:56:06Z"
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
cpes:
  - cpe:2.3:a:konflux:konflux-ci:*:*:*:*:*:*:*:*
tags:
  - credential-exposure
  - ci-cd
  - vulnerability
  - remote-code-execution
  - konflux-ci
vendors:
  - Konflux
products:
  - konflux-ci
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Continuous Integration (CI) automation scripts store sensitive GitHub access tokens in plaintext on the runner without cleaning them up after execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: An attacker with repository write access can achieve arbitrary code execution within the Continuous Integration and Continuous Delivery (CI/CD) workflow environment.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
    evidence: An attacker with repository write access can achieve arbitrary code execution within the Continuous Integration and Continuous Delivery (CI/CD) workflow environment.
    confidence_band: med
cves:
  - id: CVE-2026-114217
    cvss: 8.6
    kev_status: "false"
  - id: CVE-2026-116964
    cvss: 8.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114217
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116964
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - DevSecOps
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Rotate all GitHub access tokens used by konflux-ci
      owner: DevSecOps
      due: 24h
      evidence: Vulnerability allows retrieval of stored credentials
    - action: Audit repository write access for all Konflux-CI projects
      owner: SOC
      due: 48h
      evidence: Vulnerability requires repository write access to exploit.
  hunt_leads:
    - lead: Identify processes or users with access to runner directories after job completion
      technique_id: T1552.001
      data_needed:
        - Runner file system audit logs
        - Process execution logs on CI workers
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Tokens are left on the runner after execution
    - lead: Identify CI/CD pipeline logs showing shell execution or unexpected command output during manifest synchronization
      technique_id: T1059.004
      data_needed:
        - CI/CD pipeline execution logs
        - Shell audit logs within build containers
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attacker injects shell commands into environment export scripts.
  mitigation_plan:
    - priority: immediate
      action: Implement post-execution scripts to purge temporary files and environment variables on runners
      owner: DevSecOps
      addresses: CVE-2026-114217
      evidence: Lack of cleanup of plaintext tokens
    - priority: immediate
      action: Apply security patches or configuration hardening for Konflux-CI
      owner: IT Operations
      addresses: CVE-2026-116964
      evidence: NVD advisory CVE-2026-116964
updates:
  - at: "2026-10-31T09:56:06Z"
    level: L2
    summary: added coverage for konflux-ci
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116964
---

A vulnerability in konflux-ci involves CI automation scripts failing to sanitize sensitive GitHub access tokens after job execution. These credentials remain in plaintext on the local runner environment, allowing an attacker with local access to the runner to retrieve them and gain unauthorized repository access.

## Impact

Local attackers can leverage recovered GitHub access tokens to gain unauthorized access to connected repositories, which could facilitate unauthorized source code modifications or the tampering of release artifacts.

## Recommendation

1. Inventory all konflux-ci runner instances and audit local file systems for lingering plaintext credentials or temporary CI files.
2. Implement a post-execution cleanup process for CI runners to sanitize environment variables and temporary work directories.
3. Rotate all GitHub access tokens that have been utilized by konflux-ci automation jobs.
4. Restrict local access to CI build runners to authorized service accounts only to minimize the risk of credential exposure.
