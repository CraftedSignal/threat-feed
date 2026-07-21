---
title: Gitea Repository Migration SSRF and Internal Git Repository Exfiltration
slug: 2026-07-gitea-repo-exfil-ssrf
description: A critical vulnerability in Gitea allows an authenticated, low-privileged user to exfiltrate internal Git repositories by exploiting a validation bypass, where Gitea's initial URL validation for repository migration is circumvented by the Git command-line client's default behavior of following HTTP redirects to otherwise blocked internal IP addresses, leading to server-side request forgery (SSRF) and the theft of sensitive code, credentials, and configuration into an attacker-controlled repository, with persistent exfiltration possible through pull mirrors.
date: "2026-07-21T19:20:38Z"
lastmod: "2026-07-21T21:50:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - server-side-request-forgery
  - ssrf
  - gitea
  - vulnerability
  - code-exfiltration
  - data-exfiltration
  - information-disclosure
  - api-vulnerability
  - web-vulnerability
vendors:
  - Gitea
products:
  - Gitea
  - Gitea < 1.26.3
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The attacker obtains a low-privileged Gitea account. On instances with open registration, this may require only creating a user.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Gitea imports the internal repository contents into the attacker-controlled repository.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: 'The attacker searches the repository and full Git history for secrets: CI variables committed into workflow files. Cloud access keys. Kubernetes kubeconfigs. Terraform state files or backend credentials. Deployment SSH keys. Package registry tokens. Gitea/GitLab/GitHub PATs.'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Gitea imports the internal repository contents into the attacker-controlled repository.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Because the mirror sync path also delegates to Git, a redirecting remote can continue to redirect scheduled fetches into an internal target. New internal commits become available in the attacker's Gitea repository after mirror sync.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: The attacker uses the recovered credential to access CI/CD, cloud, container registry, deployment hosts, or orchestration infrastructure.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    evidence: An information disclosure issue in the Gitea Notification API allows users who have lost access to a private repository to continue accessing private issue or pull request information through existing notification threads.
    confidence_band: high
cves:
  - id: CVE-2026-25038
    cvss: 7.5
    epss: 0.00482
references:
  - https://github.com/advisories/GHSA-82f7-87hm-852x
  - https://github.com/advisories/GHSA-xxjv-752h-3vp2
  - https://github.com/advisories/GHSA-44qc-pgvp-wx7v
  - https://github.com/advisories/GHSA-v73x-hx65-6pf4
rules:
  - title: Gitea Git Client Connecting to RFC1918 IPs (Linux)
    description: Detects the `git` process, potentially spawned by Gitea, initiating network connections to RFC1918 private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8). This may indicate SSRF exploitation via repository migration redirect.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1078
      - T1567.002
    data_sources:
      - network_connection
      - linux
  - title: Gitea Git Client Connecting to RFC1918 IPs (Windows)
    description: Detects the `git.exe` process, potentially spawned by Gitea, initiating network connections to RFC1918 private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8). This may indicate SSRF exploitation via repository migration redirect.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1078
      - T1567.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
updates:
  - at: "2026-07-21T21:50:08Z"
    level: L2
    summary: 'merged source coverage: Gitea Notification API Leaks Private Issue Metadata After Access Revocation'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-44qc-pgvp-wx7v
  - at: "2026-07-21T21:50:25Z"
    level: L2
    summary: added CVE-2026-25038
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-v73x-hx65-6pf4
---

A critical server-side request forgery (SSRF) vulnerability has been identified in Gitea, affecting versions where repository migrations are enabled by default. This flaw enables an authenticated, low-privileged user to bypass Gitea's URL allow/block validation and exfiltrate internal Git repositories. The issue stems from a trust boundary mismatch: Gitea validates the initial public URL provided for repository migration, but the subsequent `git clone` or `git fetch --tags` operation, delegated to the Git command-line client, automatically follows HTTP redirects. Git's default `http.followRedirects=initial` setting allows an attacker to provide a public, seemingly benign URL that redirects the Gitea server to an internal Git HTTP(S) endpoint (e.g., `http://127.0.0.1:PORT/internal.git/`). This results in the Gitea server cloning internal code, configuration, and potentially sensitive credentials into an attacker-controlled repository. The vulnerability impacts all Gitea instances with repository migrations enabled, posing a significant risk for organizations hosting internal development resources, with persistent data exfiltration possible via pull mirrors continuously updating the attacker's repository.

## Attack Chain

1. An authenticated, low-privileged user gains access to a Gitea instance where repository migrations are enabled.
2. The attacker sets up a public HTTP endpoint (e.g., `https://attacker.example/public.git`) controlled by them and configured to issue an HTTP redirect.
3. The attacker configures this public endpoint to redirect the initial Git discovery request (e.g., `GET /repo.git/info/refs?service=git-upload-pack`) to an internal target, such as `http://internal-git.company.local/team/private.git/info/refs`.
4. The attacker initiates a repository migration or mirror creation in Gitea, providing the public `https://attacker.example/public.git` URL.
5. Gitea's internal validation checks and allows the `attacker.example` host, then invokes `git clone --mirror` or `git fetch --tags` using the provided public URL.
6. The `git` command-line client follows the HTTP redirect, establishing a network connection to the internal Git repository `http://internal-git.company.local/team/private.git` (or `127.0.0.1`).
7. The contents of the internal repository are cloned by the Gitea server into the attacker's newly created repository on the Gitea instance.
8. The attacker accesses the imported repository, searching for sensitive source code, CI/CD secrets, cloud credentials, Kubernetes kubeconfigs, or production configurations.

## Impact

The primary impact of this vulnerability is the unauthorized exfiltration of sensitive internal Git repositories, including proprietary source code, configuration files, and critical credentials such as CI variables, cloud access keys, Kubernetes kubeconfigs, deployment SSH keys, and API tokens. For internet-accessible Gitea instances with repository migrations enabled, this poses a high risk of significant data breach. If an attacker leverages pull mirrors, the exfiltration can become persistent, continuously updating the attacker's repository with new internal commits. Although not a direct Remote Code Execution (RCE) in Gitea itself, the stolen credentials can be subsequently used in a post-exploitation chain to gain code execution in CI/CD pipelines, cloud environments, container registries, deployment hosts, or orchestration infrastructure, potentially leading to widespread infrastructure compromise. The vulnerability affects any organization using Gitea to host internal development resources, particularly if valuable intellectual property or sensitive infrastructure secrets are stored within Git repositories.

## Recommendation

* **Disable repository migration and pull mirrors** in Gitea if they are not essential for your operational requirements, to mitigate both one-time and persistent exfiltration risks.
* **Deploy the provided Sigma rules** to your SIEM to detect suspicious `git` process network connections to internal IP addresses or private ranges.
* **Review Gitea audit logs** for unusual repository migration attempts originating from external URLs followed by internal network activity.
* **Implement strict network segmentation** and egress filtering for your Gitea server to prevent it from initiating connections to internal development infrastructure or sensitive systems that it should not access.
