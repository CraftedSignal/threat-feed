---
title: OS Command Injection in Semaphore UI via Repository Configuration
slug: 2026-09-semaphore-rce
description: An authenticated user with Manager or Owner privileges can achieve remote code execution on the Semaphore server by injecting malicious arguments into the git_url field.
date: "2026-09-08T20:04:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:semaphore_ui:semaphore:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - command-injection
  - cve-2026-73294
vendors:
  - Semaphore UI
products:
  - Semaphore (< 0.0.0-20260704181911-7e8a9434bd81)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The system's git binary parses the injected option and executes the payload through the shell.
    confidence_band: high
cves:
  - id: CVE-2026-73294
    cvss: 9.9
    epss: 0.00448
references:
  - https://github.com/advisories/GHSA-xp7j-h7jc-4w8p
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Semaphore to v0.0.0-20260704181911-7e8a9434bd81 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-73294 fix availability
  mitigation_plan:
    - priority: immediate
      action: Upgrade Semaphore to 2.18.17 or later
      owner: IT Operations
      addresses: CVE-2026-73294
      evidence: Source advisory
---

Semaphore UI is vulnerable to an OS command injection flaw (CVE-2026-73294) due to improper handling of repository configuration. An attacker with the Manager or Owner role on any project can supply a malicious git_url that leverages the git --upload-pack argument to execute arbitrary code. The vulnerability exists because the application passes the git_url verbatim to the exec.Command("git", ...) function without input validation or the use of an argument separator (--) to prevent option injection.

When the Semaphore scheduler process triggers a git ls-remote operation to poll for commit changes, the malicious git_url is interpreted as a command-line option rather than a repository path. Consequently, the git binary executes the injected command via a shell. This operation occurs within the primary Semaphore server process, allowing the attacker to bypass remote runner isolation and gain full access to the server host, including master encryption keys and all stored project secrets.

## Attack Chain

1. Attacker authenticates to the Semaphore instance with a standard Manager or Owner role.
2. Attacker creates an SSH key entry in the project to satisfy repository requirements.
3. Attacker sends a POST request to /api/project/{id}/repositories with a crafted git_url payload containing a malicious --upload-pack argument (e.g., --upload-pack=bash -c "COMMAND").
4. Attacker creates a new project template linked to the repository containing the malicious git_url.
5. Attacker creates a schedule for the project, which flags the repository for automatic polling.
6. The Semaphore server process polls the repository via the internal SchedulePool service, triggering the git ls-remote command.
7. The system git binary parses the injected option and executes the payload through the shell.
8. Attacker gains a reverse shell or executes arbitrary commands with the privileges of the Semaphore server process.

## Impact

Successful exploitation results in full remote code execution on the server host. Attackers can gain access to the application's internal database, environment variables, master encryption keys (access_key_encryption), and all secrets configured across every project in the instance. This affects any deployment using the default cmd_git client configuration.

## Recommendation

1. Upgrade Semaphore immediately to a version containing the patch for CVE-2026-73294 (v0.0.0-20260704181911-7e8a9434bd81 or later).
2. Audit user permissions within the platform to identify and revoke excessive Manager or Owner roles assigned to untrusted accounts.
3. Implement egress filtering on the Semaphore server host to prevent unexpected outbound connections (e.g., reverse shells) initiated by the application process.
