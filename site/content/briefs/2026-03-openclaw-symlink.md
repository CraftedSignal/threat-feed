---
title: OpenClaw Symlink Traversal via IDENTITY.md appendFile in agents.create/update
slug: 2026-03-openclaw-symlink
description: OpenClaw is vulnerable to symlink traversal via IDENTITY.md appendFile in agents.create/update. An attacker who can place a symlink in the agent workspace can hijack the IDENTITY.md path to append attacker-controlled content to arbitrary files on the system leading to remote code execution, persistent code execution, unauthorized SSH access, or service disruption.
date: "2026-03-27T14:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - openclaw
  - symlink-traversal
  - vulnerability
  - npm
  - rce
  - persistence
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Privilege Escalation
references:
  - https://github.com/advisories/GHSA-7xr2-q9vf-x4r5
rules:
  - title: Detect OpenClaw Symlink Traversal Attempt via fs.appendFile
    description: Detects attempts to exploit the OpenClaw symlink traversal vulnerability by monitoring for fs.appendFile calls to IDENTITY.md without symlink resolution within agent workspace directories.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1202
      - T1547
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Creation of Symlink to Sensitive File
    description: Detects the creation of a symbolic link inside an agent workspace directory pointing to a sensitive system file like /etc/crontab or ~/.ssh/authorized_keys.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The `openclaw` npm package is vulnerable to a symlink traversal vulnerability (CVE-2026-32013) affecting versions 2026.2.22 and earlier. The vulnerability lies in the `agents.create` and `agents.update` handlers within the `src/gateway/server-methods/agents.ts` file. These handlers use `fs.appendFile` on the `IDENTITY.md` file without proper symlink containment checks. An attacker capable of placing a symlink within the agent workspace can redirect the `IDENTITY.md` path to point to arbitrary files on the system, allowing them to append attacker-controlled content to these files. This can lead to serious consequences such as remote code execution by modifying `/etc/crontab`, persistent code execution by modifying shell configuration files like `~/.bashrc`, or unauthorized SSH access by modifying `~/.ssh/authorized_keys`.

## Attack Chain

1.  The attacker gains initial access to the agent workspace.
2.  The attacker plants a symbolic link named `IDENTITY.md` within the agent workspace. This symlink points to a sensitive system file, such as `/etc/crontab` or `~/.ssh/authorized_keys`.
3.  The `ensureAgentWorkspace` function is called, but the exclusive-create flag (`wx`) skips creation due to the existing symlink (EEXIST error).
4.  The attacker triggers the `agents.create` or `agents.update` API endpoint, for example, by sending an HTTP POST request.
5.  The `agents.create` or `agents.update` handler constructs the path to `IDENTITY.md` using `path.join(workspaceDir, DEFAULT_IDENTITY_FILENAME)`.
6.  The vulnerable `fs.appendFile` function is called to append agent metadata (name, emoji, avatar) to the `IDENTITY.md` file. Because `fs.appendFile` follows symlinks, the content is written to the attacker-controlled target file.
7.  Attacker-controlled data is appended to the target file.
8.  If the target file is a cron configuration file, this leads to remote code execution. If it's an SSH authorized_keys file, this leads to unauthorized access.

## Impact

Successful exploitation allows an attacker to append attacker-controlled content to arbitrary files on the system. This can lead to:

-   **Remote Code Execution:** By appending malicious entries to `/etc/crontab` or user crontab files.
-   **Persistent Code Execution:** By modifying shell configuration files like `~/.bashrc` or `~/.profile`.
-   **Unauthorized SSH Access:** By appending SSH keys to `~/.ssh/authorized_keys`.
-   **Service Disruption:** By modifying application configuration files.

The vulnerability affects `openclaw` versions 2026.2.22 and earlier, and no patches are currently available. The number of affected systems depends on the adoption rate of the `openclaw` package.

## Recommendation

*   Monitor file creation events within agent workspace directories for the creation of symbolic links using file_event logs.
*   Implement and deploy the provided Sigma rule to detect exploitation attempts by monitoring `fs.appendFile` calls related to IDENTITY.md without symlink resolution.
*   Restrict access to the agent workspace directory to prevent attackers from planting symlinks.
*   Upgrade to a patched version of `openclaw` when available.
