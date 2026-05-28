---
title: Gogs Zero-Day Vulnerability Enables Remote Code Execution
slug: 2026-05-gogs-rce
description: An unpatched argument injection vulnerability in Gogs (versions 0.14.2 and 0.15.0+dev) allows authenticated attackers to achieve remote code execution (RCE) on vulnerable instances, potentially leading to complete server compromise.
date: "2026-05-28T14:26:36Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:gogs:gogs:*:*:*:*:*:*:*:*
tags:
  - rce
  - zero-day
  - argument injection
vendors:
  - Gogs
products:
  - Gogs 0.14.2
  - Gogs 0.15.0+dev
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2025-8110
    cvss: 8.8
    epss: 0.22347
  - id: CVE-2024-39933
    cvss: 7.7
    epss: 0.00264
  - id: CVE-2024-39932
    cvss: 9.9
    epss: 0.03233
  - id: CVE-2026-26194
    cvss: 7.3
    epss: 0.00051
  - id: CVE-2024-39930
    cvss: 9.9
    epss: 0.11879
references:
  - https://www.bleepingcomputer.com/news/security/new-gogs-zero-day-flaw-lets-hackers-get-remote-code-execution/
  - CVE-2024-39933
  - CVE-2024-39932
  - CVE-2026-26194
  - CVE-2024-39930
  - CVE-2025-8110
rules:
  - title: Detect Suspicious Git Rebase Command Execution
    description: 'Detects suspicious git rebase command execution potentially indicative of argument injection vulnerability exploitation in Gogs. '
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: Detect Outbound Connection from Gogs Server
    description: Detects outbound network connections from Gogs server processes, which may indicate command and control activity following successful exploitation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A zero-day vulnerability has been discovered in Gogs, a self-hosted Git service, affecting versions 0.14.2 and 0.15.0+dev. This critical severity flaw is an argument injection vulnerability that allows authenticated attackers to execute arbitrary code remotely on Internet-facing Gogs instances with default configurations. The vulnerability stems from a failure to properly sanitize input during the "Rebase before merging" merge operation, specifically within the Merge() function. An attacker can exploit this flaw by creating a malicious branch name within a pull request. This issue was reported to Gogs maintainers on March 17, 2026, but remains unpatched as of May 2026.

## Attack Chain

1. An unauthenticated attacker registers a new user account on a Gogs instance due to open registration being enabled by default.
2. The attacker creates a new repository as the newly registered user. There are no limits to repository creation on default-configured instances.
3. The attacker, now the owner of the repository, enables the "Rebase before merging" option in the repository settings.
4. The attacker creates a malicious branch with a specially crafted name designed to inject the "&mdash;exec" flag into the `git rebase` command.
5. The attacker initiates a pull request targeting the main branch, incorporating the malicious branch.
6. The Gogs server attempts to perform a "Rebase before merging" operation, triggering the vulnerability due to the injected arguments.
7. The injected `git rebase` command executes arbitrary code as the Gogs server process user.
8. The attacker gains full control of the Gogs server, allowing them to read all repositories, dump credentials, pivot to other systems, and modify any hosted repository's code.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary code remotely as the Gogs server process user. This grants them the ability to compromise the server, access all repositories (including private ones), dump credentials (password hashes, API tokens, SSH keys, 2FA secrets), pivot to other network-accessible systems, and modify any hosted repository's code. Shadowserver tracks over 2,400 Gogs servers exposed online, and Shodan identifies over 1,000 IP addresses with a Gogs fingerprint, making this a widespread threat. In December 2025, CVE-2025-8110, another Gogs RCE vulnerability, was actively exploited to compromise hundreds of servers, highlighting the potential for rapid exploitation of this new flaw.

## Recommendation

*   Until a patch is available, consider disabling open registration (`DISABLE_REGISTRATION = true`) to prevent unauthenticated users from creating accounts and repositories.
*   Monitor process execution for unexpected `git rebase` commands originating from the Gogs server process, using the "Detect Suspicious Git Rebase Command Execution" Sigma rule to identify potential exploitation attempts.
*   Inspect network traffic for suspicious outbound connections originating from Gogs servers, which could indicate successful exploitation and lateral movement, using the "Detect Outbound Connection from Gogs Server" Sigma rule.
*   Review and harden Gogs configurations to limit repository creation (`MAX_CREATION_LIMIT`) to reduce the attack surface.
