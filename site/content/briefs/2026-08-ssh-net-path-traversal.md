---
title: Arbitrary File Write Vulnerability in SSH.NET ScpClient
slug: 2026-08-ssh-net-path-traversal
description: A path traversal vulnerability in the SSH.NET ScpClient allows a malicious SCP server to write or overwrite arbitrary files on a client machine during a recursive directory download.
date: "2026-08-12T16:48:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - path-traversal
  - dotnet
products:
  - SSH.NET (<= 2025.1.0)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Overwriting files such as ~/.ssh/authorized_keys, shell rc files, cron entries, or application binaries/config can lead to persistence.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-q939-rpr3-3284
  - https://github.com/sshnet/SSH.NET/commit/600be0de543765995a189b5d7cd4efac5007f3ce
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Update SSH.NET dependency to version > 2025.1.0
      owner: IT Operations
      due: 72h
      evidence: Source advisory confirms patch availability
  mitigation_plan:
    - priority: immediate
      action: Restrict SCP client access to trusted servers only
      owner: IT Operations
      addresses: CVE-2026-48798
      evidence: Vulnerability requires an attacker-controlled server
---

SSH.NET, a popular SSH library for .NET, contains a directory traversal vulnerability (CVE-2026-48798) in the `ScpClient` component. When performing a recursive download of a directory, the library fails to sanitize filenames returned by the remote SCP server. A malicious or compromised SCP server can provide filenames containing directory traversal sequences (such as `../`) or absolute paths. 

If a client application uses `ScpClient.Download` to pull a directory from an untrusted or compromised server, the library will construct local file paths based on these unsanitized names. This allows the attacker to write files outside of the intended target directory, potentially overwriting sensitive files such as SSH authorized keys, user profile startup scripts (e.g., .bashrc, .profile), or application configuration files. This vulnerability effectively grants the attacker the ability to perform operations with the privileges of the user running the .NET application. The issue was addressed in the project's commit history, and users are advised to upgrade to the latest version to prevent malicious path traversal during SCP operations.

## Impact

The impact of this vulnerability is significant, as it enables arbitrary file write capabilities on the host running the application. Successful exploitation could lead to privilege escalation or remote code execution by overwriting critical system or user files (e.g., `~/.ssh/authorized_keys`, `~/.bashrc`, or cron jobs). The threat specifically targets environments where automated, recurring backups or data synchronization tasks are performed using SSH.NET against untrusted or potentially compromised remote infrastructure.

## Recommendation

- Upgrade the SSH.NET NuGet package to the latest version that includes the fix for CVE-2026-48798.
- Audit all applications utilizing `SSH.NET` to determine if `ScpClient.Download` is used to sync data from external, non-hardened SCP servers.
- Review application-level access controls for the user account executing the SSH.NET library to minimize the impact of a potential write primitive (adhere to principle of least privilege).
- Monitor logs for unusual directory creation or file write events initiated by .NET applications performing network synchronization tasks.
