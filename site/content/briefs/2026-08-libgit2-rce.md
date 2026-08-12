---
title: Command Injection in libgit2 via libssh2 Backend
slug: 2026-08-libgit2-rce
description: A command injection vulnerability in libgit2 versions v0.27.0 through v1.9.0 allows remote code execution during recursive repository clones when using the libssh2 SSH backend.
date: "2026-08-12T01:53:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - libgit2
products:
  - libgit2 (v0.27.0 through v1.9.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The gen_proto() function in ssh_libssh2.c inserts the repository path directly into a shell command string without escaping special characters before passing it to libssh2_channel_exec(), enabling an attacker to craft a malicious submodule URL in a .gitmodules file that, when processed during a recursive clone, causes the remote server's shell to interpret injected commands.
    confidence_band: high
cves:
  - id: CVE-2026-5917
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5917
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development Teams
  immediate_actions:
    - action: Upgrade libgit2 to version 1.9.1 or higher across all development and production environments
      owner: IT Operations
      due: 48h
      evidence: libgit2 versions v0.27.0 through v1.9.0 contain a shell command injection vulnerability
  mitigation_plan:
    - priority: immediate
      action: Identify applications using libgit2 with libssh2 backend via system audit
      owner: Development Teams
      addresses: CVE-2026-5917
      evidence: libgit2 versions v0.27.0 through v1.9.0 built with the libssh2 SSH backend contain a shell command injection vulnerability
---

libgit2 versions v0.27.0 through v1.9.0 are vulnerable to command injection when compiled with the libssh2 SSH backend (USE_SSH=libssh2). The flaw resides in the gen_proto() function within ssh_libssh2.c, which fails to sanitize repository path inputs before concatenating them into shell command strings. This vulnerability allows an attacker to achieve remote code execution by forcing a user or system to perform a recursive git clone of a repository containing a maliciously crafted .gitmodules file. When the client processes the submodule URL, the injected shell metacharacters - such as single quotes, semicolons, or pipes - are interpreted by the remote server's shell. This execution occurs with the privileges of the user running the git operation, posing a significant risk to CI/CD pipelines, developer workstations, and automated server environments that rely on libgit2 for repository management.

## Impact

Successful exploitation allows remote attackers to execute arbitrary shell commands under the context of the user or service account performing a git clone operation. This impacts any software, CI/CD pipeline, or automated system utilizing affected libgit2 versions, potentially leading to full system compromise, exfiltration of credentials stored in SSH agents, or lateral movement within build environments.

## Recommendation

* Update all instances of libgit2 to version 1.9.1 or later to resolve the underlying vulnerability in the gen_proto() function.
* Audit build environments and CI/CD configurations to identify applications linked against the libssh2 SSH backend of libgit2.
* Monitor git operations for unexpected recursive submodule processing, particularly those targeting unknown or untrusted external repositories.
* Implement strict path validation and utilize SSH configurations that restrict command execution for services performing automated clones.
