---
title: Gogs Remote Code Execution via git rebase --exec Argument Injection (GHSA-qf6p-p7ww-cwr9)
slug: 2026-07-gogs-rce
description: Gogs, a self-hosted Git service, is vulnerable to a Critical (CVSS 9.9) Remote Code Execution (RCE) via `git rebase --exec` argument injection (GHSA-qf6p-p7ww-cwr9) during pull request merge operations, allowing an authenticated attacker to execute arbitrary commands as the Gogs server process user and achieve full server compromise.
date: "2026-07-03T11:00:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - gogs
  - git
  - code-repository
  - vulnerability
  - argument-injection
  - server-side-request-forgery
vendors:
  - Gogs
products:
  - Gogs 0.14.2
  - Gogs 0.15.0+dev
  - Gogs (All prior versions)
affected_os:
  - Linux
  - macOS
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Gogs allows authenticated users to achieve Remote Code Execution (RCE)
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The `--exec` flag specifies a command to run via `sh -c` after each replayed commit
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This is a privilege escalation from authenticated user to server-level code execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: The exploit leaves minimal traces (a 500 error in server logs, easily missed)
    confidence_band: med
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: 'Supply chain attacks: Silently modify any hosted repository''s code.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-qf6p-p7ww-cwr9
rules:
  - title: Detect Gogs GHSA-qf6p-p7ww-cwr9 Exploitation via git rebase --exec
    description: Detects the exploitation attempt of GHSA-qf6p-p7ww-cwr9 in Gogs, where an authenticated user injects the --exec argument into 'git rebase' during a pull request merge to achieve arbitrary command execution. This rule looks for the suspicious command-line pattern.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical Remote Code Execution (RCE) vulnerability, identified as GHSA-qf6p-p7ww-cwr9, affects Gogs, the self-hosted Git service, specifically versions 0.14.2, 0.15.0+dev (prior to commit `b53d3162`), and all prior versions supporting "Rebase before merging" merge styles. This vulnerability allows any authenticated user to achieve RCE on the underlying server by crafting a malicious branch name that injects the `--exec` flag into the `git rebase` command during a pull request merge. The exploit results in privilege escalation from a regular user to server-level code execution, enabling full compromise, cross-tenant data breaches, and supply chain attacks. The severity is heightened by Gogs's default open registration (`DISABLE_REGISTRATION = false`) and the fact that any user can create a repository and enable the "Rebase before merging" option without administrator intervention, effectively making the vulnerability exploitable with minimal prerequisites and leaving minimal traces in logs.

## Attack Chain

1.  **Initial Access**: An attacker obtains an authenticated account on the Gogs instance, either through open registration or by compromising existing credentials.
2.  **Repository Setup**: The attacker creates their own repository (or gains write access to one where "Rebase before merging" is enabled) and then enables the "Rebase before merging" option in the repository settings.
3.  **Malicious Branch Creation**: The attacker creates a new branch in their repository with a specially crafted name, such as `--exec=touch${IFS}/tmp/rce_proof`, which abuses the `git rebase --exec` argument.
4.  **Pull Request Submission**: The attacker creates a pull request (PR) targeting their own repository's base branch from their malicious branch.
5.  **Merge Operation Initiation**: The attacker initiates the "Rebase before merging" operation for the malicious pull request through the Gogs web interface.
6.  **Remote Code Execution**: During the rebase process, Gogs executes the `git rebase` command with the attacker's crafted branch name. Git interprets `--exec=...` as an argument, causing the embedded command (`touch /tmp/rce_proof` or a base64-encoded payload) to execute on the Gogs server as the Gogs process user (typically `git`).
7.  **Server Compromise/Impact**: Despite a subsequent `git checkout` failure leading to an HTTP 500 error in Gogs, the RCE has already successfully completed, giving the attacker full control over the server.

## Impact

Successful exploitation of this vulnerability leads to severe consequences, including full server compromise. An attacker gains arbitrary command execution as the Gogs process user, which can lead to cross-tenant data breaches, allowing them to read all repositories on the instance, including other users' private code. This can also facilitate credential theft, providing access to password hashes, API tokens, SSH keys, and 2FA secrets for every user. Furthermore, the attacker can use the compromised server for lateral movement into other internal systems and can conduct supply chain attacks by silently modifying any hosted repository's code. This critical vulnerability affects all Gogs installations regardless of the operating system (Linux, macOS, Windows) or deployment method (binary, Docker, source), posing a significant threat to the integrity and confidentiality of code hosted on Gogs instances.

## Recommendation

*   **Patch Immediately**: Upgrade Gogs to a version that contains the fix for GHSA-qf6p-p7ww-cwr9. As of the advisory, a patch was not explicitly mentioned, but the issue is tied to `b53d3162` commit. Monitor Gogs releases for official patch availability.
*   **Implement Process Monitoring**: Deploy the Sigma rule in this brief to your SIEM to detect `git rebase` commands containing the `--exec=` argument. Ensure your endpoint detection and response (EDR) or Sysmon configuration captures process creation events, including command-line arguments and parent-child relationships, on Gogs server hosts.
*   **Review Gogs Configuration**: If patching is not immediately possible, consider disabling the "Rebase before merging" option globally or restricting user permissions to prevent its enablement on repositories until a patch is applied.
*   **Monitor Gogs Application Logs**: Regularly review Gogs application logs for error messages indicating `git checkout '--exec=<...>': exit status 128 - error: unknown option \`exec=<...>''`, which signifies a post-RCE attempt to check out the malicious branch.
