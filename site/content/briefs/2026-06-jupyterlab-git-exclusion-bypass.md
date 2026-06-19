---
title: JupyterLab-Git excluded_paths Case-Sensitivity Bypass (CVE-2026-54528)
slug: 2026-06-jupyterlab-git-exclusion-bypass
description: An authenticated user can bypass the admin-configured `excluded_paths` security control in `jupyterlab-git` versions up to 0.53.0 by exploiting a case-sensitivity flaw on case-insensitive filesystems (e.g., macOS APFS, Windows NTFS), allowing unauthorized read access to git history and file content in explicitly excluded directories.
date: "2026-06-19T19:59:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - path-traversal
  - data-exfiltration
  - jupyterlab
  - python
vendors:
  - Project Jupyter
products:
  - jupyterlab-git <= 0.53.0
affected_os:
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://github.com/advisories/GHSA-436q-jwfr-rm2h
rules:
  - title: Detects CVE-2026-54528 Exploitation - JupyterLab-Git Status Bypass
    description: Detects HTTP POST requests to JupyterLab-Git '/status' endpoints that indicate a potential bypass of 'excluded_paths' via case-insensitive path segments, returning a 200 OK status. This suggests an attacker is checking access to a directory that should be restricted.
    platform: sigma
    severity: high
    tactics:
      - collection
      - defense_evasion
    techniques:
      - T1078
      - T1083
    data_sources:
      - webserver
  - title: Detects CVE-2026-54528 Exploitation - JupyterLab-Git Content Exfiltration Bypass
    description: Detects HTTP POST requests to JupyterLab-Git '/content' endpoints that indicate a potential bypass of 'excluded_paths' via case-insensitive path segments, resulting in sensitive file content retrieval (200 OK status). This suggests an attacker is exfiltrating data from a restricted directory.
    platform: sigma
    severity: high
    tactics:
      - collection
      - exfiltration
    techniques:
      - T1005
      - T1041
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability, tracked as CVE-2026-54528, has been discovered in `jupyterlab-git` versions up to 0.53.0, a popular Git extension for JupyterLab environments. This flaw allows an authenticated user to bypass security controls designed to restrict access to sensitive directories. The vulnerability stems from the `jupyterlab-git` extension's use of `fnmatch.fnmatchcase()` for enforcing `excluded_paths` configurations. Unlike `fnmatch.fnmatch()`, `fnmatch.fnmatchcase()` is unconditionally case-sensitive. This design choice enables attackers on case-insensitive filesystems (such as Windows NTFS or macOS APFS) to craft URLs with case-varied path segments (e.g., `/project/Secrets` instead of `/project/secrets`), thereby circumventing the exclusion logic and gaining unauthorized read access to Git repositories and file contents within directories explicitly forbidden by administrators. This directly impacts data confidentiality and integrity.

## Attack Chain

1.  An authenticated user with valid access to a JupyterLab instance, running a vulnerable version of `jupyterlab-git` (<=0.53.0), is present on a system with a case-insensitive filesystem (Windows NTFS or macOS APFS).
2.  An administrator has configured `c.JupyterLabGit.excluded_paths` to deny access to sensitive directories (e.g., `["/project/secrets", "/project/secrets/*"]`).
3.  The attacker identifies a sensitive path that should be excluded (e.g., `/project/secrets`) and crafts an HTTP `POST` request to a `jupyterlab-git` endpoint (e.g., `/git/{path}/status`) using a case-varied version of the path (e.g., `/git/project/Secrets/status`).
4.  The `jupyterlab-git` backend, specifically `GitHandler.prepare()`, checks the crafted path against `excluded_paths` using `fnmatch.fnmatchcase()`. Due to the unconditional case-sensitivity of `fnmatch.fnmatchcase()`, the path `/project/Secrets` does not match the configured `/project/secrets`, bypassing the exclusion check.
5.  On the case-insensitive filesystem, the `url2localpath()` function resolves `/project/Secrets` to the same disk location as `/project/secrets`, allowing the request to proceed to the target directory.
6.  The attacker first confirms the bypass by sending a `POST` request to an information-gathering endpoint like `/git/project/Secrets/status`, which returns a `200 OK` status instead of the expected `404` error.
7.  With confirmed access, the attacker sends a `POST` request to the `/git/project/Secrets/content` endpoint, providing a filename (e.g., `{"filename": "./cred.txt", "reference": {"git": "HEAD"}}`), to exfiltrate the contents of sensitive files.
8.  The JupyterLab server returns the content of the sensitive file (e.g., `sk-PROD-a8f2x9q-LIVE-KEY`), resulting in unauthorized data exposure.

## Impact

Successful exploitation of CVE-2026-54528 leads to the unauthorized disclosure of sensitive information. An authenticated attacker can access Git history, working tree files, and status information for any directory that an administrator intended to exclude, provided the underlying filesystem is case-insensitive. This directly compromises the confidentiality of data stored in affected repositories, including credentials, proprietary code, or confidential documents. The observed impact demonstrates the exfiltration of a simulated API key from an excluded `secrets` directory. Organizations using `jupyterlab-git` on Windows or macOS systems are at risk, with the potential for widespread data breaches if critical information is stored in such Git-managed directories.

## Recommendation

Prioritize patching and detection to mitigate CVE-2026-54528.
*   Immediately upgrade `jupyterlab-git` to a version greater than 0.53.0 to apply the fix for CVE-2026-54528.
*   Deploy the provided Sigma rules "Detects CVE-2026-54528 Exploitation - JupyterLab-Git Status Bypass" and "Detects CVE-2026-54528 Exploitation - JupyterLab-Git Content Exfiltration Bypass" to your SIEM solution to detect attempts to bypass `excluded_paths` via case-varied URLs.
*   Ensure detailed `webserver` logging is enabled for all JupyterLab instances to capture HTTP `POST` requests, URI stems, and status codes for analysis.
*   Review web server logs for `POST` requests to `/git/*/status` and `/git/*/content` endpoints returning `200 OK` where paths contain common sensitive keywords (e.g., `secrets`, `config`) with mixed casing, cross-referencing with your `excluded_paths` configuration.
