---
title: Multiple Critical Vulnerabilities in Gogs Allow Remote Code Execution and Data Compromise
slug: 2026-06-gogs-rce-patch
description: Multiple critical vulnerabilities in Gogs versions prior to 0.14.3, including remote code execution (RCE) flaws (CVE-2026-52813, CVE-2026-52806) and arbitrary file write capabilities (CVE-2026-52811), enable attackers to achieve full host operating system takeover, steal proprietary source code, and facilitate lateral movement.
date: "2026-06-26T08:03:31Z"
lastmod: "2026-07-21T16:01:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=0D713120-944A-54D1-8462-A83F53952638&utm_source=rss&utm_medium=rss
tags:
  - rce
  - path-traversal
  - command-injection
  - git
  - web-application
  - gogs
vendors:
  - Gogs
products:
  - Gogs (< 0.14.3)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A Remote Code Execution (RCE) vulnerability caused by path traversal...triggered by improper sanitization of organization names accepted through the API
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: allowing an attacker to manipulate server file paths and execute arbitrary commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: An authenticated Remote Code Execution (RCE) vulnerability via argument injection...by injecting the --exec flag into the git rebase command during a 'Rebase before merging' action.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
    evidence: An attacker with standard user privileges can achieve RCE by creating a pull request with a maliciously crafted branch name.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1561
    technique_name: Disk Wipe
    evidence: An arbitrary file write vulnerability allowing modifications outside the repository working tree.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1561
    technique_name: ""
    evidence: This has the potential impact of full host operating system takeover
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: theft of proprietary source code
    confidence_band: high
cves:
  - id: CVE-2026-52813
    cvss: 10
    epss: 0.01107
  - id: CVE-2026-52806
    cvss: 9.9
    epss: 0.01029
  - id: CVE-2026-52811
    epss: 0.00474
references:
  - https://ccb.belgium.be/advisories/warning-multiple-vulnerabilities-gogs-allow-remote-code-execution-patch-immediately
  - https://github.com/gogs/gogs/security/advisories/GHSA-c39w-43gm-34h5
  - https://github.com/gogs/gogs/security/advisories/GHSA-qf6p-p7ww-cwr9
  - https://github.com/gogs/gogs/security/advisories/GHSA-89mr-xqfv-758m
  - https://github.com/gogs/gogs/releases
  - https://sploitus.com/exploit?id=0D713120-944A-54D1-8462-A83F53952638&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=0D713120-944A-54D1-8462-A83F53952638
  - type: url
    value: https://github.com/gogs/gogs/security/advisories/GHSA-c39w-43gm-34h5
  - type: url
    value: https://osv.dev/vulnerability/CVE-2026-52813
  - type: url
    value: https://github.com/gogs/gogs/pull/8334
  - type: url
    value: https://github.com/gogs/gogs/releases/tag/v0.14.3
  - type: url_pattern
    value: POST /api/v1/user/orgs
  - type: url_pattern
    value: POST /api/v1/org/*/repos
  - type: file_path
    value: /data/gogs/data/tmp/local-r/
  - type: other
    value: GHSA-c39w-43gm-34h5
  - type: other
    value: GO-2026-5305
ioc_counts:
  file_path: 1
  other: 2
  url: 5
  url_pattern: 2
updates:
  - at: "2026-07-21T16:01:57Z"
    level: L2
    summary: poc_available; added CVE-2026-52806 +2
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=0D713120-944A-54D1-8462-A83F53952638&utm_source=rss&utm_medium=rss
---

The Centre for Cybersecurity Belgium (CCB) has issued an urgent advisory warning of multiple critical vulnerabilities affecting Gogs, a self-hosted Git service, in versions prior to 0.14.3. These flaws, including CVE-2026-52813 (CVSS 10.0), CVE-2026-52806 (CVSS 9.9), and CVE-2026-52811 (CVSS 9.0), introduce significant risks such as remote code execution, path traversal, command injection, and arbitrary file write capabilities. Attackers can leverage these weaknesses to bypass application boundaries, manipulate server file paths, and execute arbitrary commands. The vulnerabilities pose a severe threat, potentially leading to full host operating system takeover, exfiltration of proprietary source code, and subsequent lateral movement into connected corporate infrastructure. Organizations using affected Gogs installations are strongly urged to patch immediately.

## Attack Chain

1.  **Initial Access / API Interaction (CVE-2026-52813):** An unauthenticated attacker sends a crafted API request containing a malicious organization name to a vulnerable Gogs instance.
2.  **Path Traversal & Command Execution (CVE-2026-52813):** The Gogs server processes the unsanitized organization name, triggering a path traversal vulnerability that allows arbitrary command execution on the underlying operating system.
3.  **OR Authenticated Access & Malicious Pull Request (CVE-2026-52806):** An attacker with standard user privileges creates a pull request using a maliciously crafted branch name.
4.  **Argument Injection & Remote Code Execution (CVE-2026-52806):** A privileged user (e.g., administrator) initiates a "Rebase before merging" action on the malicious pull request, causing argument injection into the `git rebase` command, leading to remote code execution on the Gogs server.
5.  **OR Arbitrary File Write Setup (CVE-2026-52811):** An attacker commits a directory symlink to a repository hosted on the vulnerable Gogs instance.
6.  **Arbitrary File Write (CVE-2026-52811):** The attacker then uploads a crafted filename. When this file is processed, it is routed through the previously committed symlink, enabling the attacker to write arbitrary files outside the repository's working directory, potentially overwriting sensitive system files.
7.  **Impact & System Takeover:** Successful exploitation of any of these RCE or arbitrary file write vulnerabilities leads to full host operating system takeover, enabling theft of proprietary source code and subsequent lateral movement within the connected corporate infrastructure.

## Impact

The successful exploitation of these critical Gogs vulnerabilities (CVE-2026-52813, CVE-2026-52806, CVE-2026-52811) carries severe consequences. Attackers can achieve full host operating system takeover, gain complete control over the server, and steal proprietary source code or other sensitive data. The ability to execute arbitrary code and write files outside the repository working tree allows for extensive system compromise, including the potential for installing backdoors, maintaining persistence, and facilitating lateral movement into connected corporate infrastructure and production networks. This could severely disrupt operations, lead to significant data breaches, and compromise the integrity of development pipelines.

## Recommendation

*   **Patch CVE-2026-52813, CVE-2026-52806, and CVE-2026-52811** by upgrading Gogs instances to version 0.14.3 or later immediately.
*   **Implement enhanced monitoring** to identify any suspicious API requests, unusual `git rebase` command executions, or unexpected file write activities originating from Gogs servers, particularly for instances affected by CVE-2026-52813, CVE-2026-52806, and CVE-2026-52811.
*   **Review Gogs logs for evidence of exploitation** related to CVE-2026-52813 (malicious organization names in API requests), CVE-2026-52806 (crafted branch names in pull requests and `git rebase` executions), and CVE-2026-52811 (unusual file writes from Gogs processes).
