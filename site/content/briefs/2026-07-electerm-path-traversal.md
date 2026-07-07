---
title: electerm Path Traversal Vulnerability in Zmodem and Trzsz Download Handling (CVE-2026-49253)
slug: 2026-07-electerm-path-traversal
description: A path traversal vulnerability exists in electerm's Zmodem and Trzsz file download handlers (CVE-2026-49253), allowing a malicious SSH server to send specially crafted filenames (e.g., `../escaped.txt`) that, when accepted by the user, can cause files to be written to arbitrary locations on the user's filesystem, potentially overwriting sensitive files or introducing malicious content.
date: "2026-07-03T11:38:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - vulnerability
  - client-side
  - terminal-emulator
  - file-transfer
vendors:
  - electerm
products:
  - electerm (<= 3.11.0)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A path traversal vulnerability exists in the Zmodem and Trzsz file download handlers in electerm. When receiving files via Zmodem or Trzsz protocols, electerm uses the remote-supplied filename directly... A malicious SSH server or remote shell process can send a specially crafted filename...
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: A malicious SSH server or remote shell process can send a specially crafted filename such as `../escaped.txt` to escape the user-selected download directory and write files to arbitrary locations on the user's filesystem...
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: File is written outside the selected directory, potentially overwriting sensitive files
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-38j7-23hf-9mhc
  - https://github.com/electerm/electerm/commit/fde153d677a170c5816368f6586647f3af4ef284
---

A significant path traversal vulnerability, tracked as CVE-2026-49253, has been identified in electerm, a popular terminal emulator. This flaw affects the Zmodem and Trzsz file download handlers in versions up to and including 3.11.0. The vulnerability stems from electerm's failure to sanitize remote-supplied filenames when combining them with the user-selected download directory path. This allows a malicious SSH server or remote shell process to provide filenames like `../escaped.txt`, effectively escaping the intended download directory. Consequently, files can be written to arbitrary locations on the user's filesystem, subject to the permissions of the electerm process. This could lead to severe consequences such as overwriting critical system files, altering user configuration, or deploying malicious payloads, posing a substantial risk to user data integrity and system security.

## Attack Chain

1.  An attacker establishes control over an SSH server or gains access to a remote shell session.
2.  A user of electerm connects to this attacker-controlled SSH server.
3.  The attacker initiates a Zmodem (`rz` or `sz`) or Trzsz (`trz` or `tsz`) file transfer protocol session.
4.  During the transfer, the attacker supplies a specially crafted filename containing directory traversal sequences (e.g., `../../.bashrc`, `../escaped.txt`).
5.  The electerm client receives the file transfer request and presents it to the user.
6.  The user accepts the transfer and selects an intended download directory within electerm.
7.  Due to the vulnerability in `path.join()`, electerm processes the unsanitized filename, causing the file to be written outside the user-selected download directory.
8.  The malicious file is written to an arbitrary location on the user's filesystem, potentially overwriting sensitive configuration files, system binaries, or dropping new malicious executables, achieving data destruction or persistence.

## Impact

This path traversal vulnerability poses a high risk to users of electerm. If exploited, an attacker could write arbitrary files to any location on the victim's filesystem where the electerm process has write permissions. This could lead to the overwrite or corruption of critical system files, user configuration files (e.g., `~/.bashrc`, `~/.ssh/authorized_keys`), or the injection of malicious scripts or binaries. The direct consequences include system instability, loss of data integrity, unauthorized access (if configuration files are tampered with), and potentially full system compromise. There is no specific victim count available, but all users running vulnerable versions of electerm are at risk, regardless of their sector.

## Recommendation

*   Immediately update electerm to a patched version to remediate CVE-2026-49253.
*   Instruct users to avoid connecting to untrusted SSH servers.
*   Advise users to reject or cancel any incoming Zmodem or Trzsz file transfers if they originate from untrusted sources.
*   Educate users on the risks of using Zmodem (`sz`/`rz`) and Trzsz (`trz`/`tsz`) commands when interacting with untrusted or potentially compromised remote servers.
