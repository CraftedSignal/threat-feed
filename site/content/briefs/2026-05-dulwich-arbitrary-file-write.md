---
title: Dulwich Arbitrary File Write Vulnerability on Windows (CVE-2026-42305)
slug: 2026-05-dulwich-arbitrary-file-write
description: Dulwich versions before 1.2.5 are vulnerable to an arbitrary file write leading to remote code execution on Windows systems when cloning or checking out a malicious Git repository due to improper path validation, as tracked by CVE-2026-42305.
date: "2026-05-28T22:30:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:git-scm:git:*:*:*:*:*:*:*:*
  - cpe:2.3:o:opensuse:leap:15.1:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:visual_studio_2017:*:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:visual_studio_2019:*:*:*:*:*:*:*:*
tags:
  - arbitrary-file-write
  - remote-code-execution
  - git
  - dulwich
vendors:
  - Dulwich
products:
  - dulwich (< 1.2.5)
affected_os:
  - Windows
cves:
  - id: CVE-2019-1353
    cvss: 9.8
    epss: 0.00129
  - id: CVE-2019-1354
    cvss: 8.8
    epss: 0.19687
references:
  - https://github.com/advisories/GHSA-897w-fcg9-f6xj
  - https://github.com/git/git/blob/master/path.c
  - CVE-2019-1353
  - CVE-2019-1354
rules:
  - title: Detect Dulwich Git Hook Write via Malicious Filename
    description: Detects the creation of a Git hook file with a filename containing a backslash, indicative of a malicious Dulwich clone attempting to plant a hook (CVE-2026-42305).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - file_event
      - windows
  - title: Detect Dulwich Alternate Data Stream Write Attempt
    description: Detects attempts to write to an NTFS alternate data stream within the .git directory using a colon in the filename (CVE-2026-42305).
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Dulwich versions before 1.2.5 are vulnerable to an arbitrary file write vulnerability (CVE-2026-42305) on Windows. The vulnerability occurs because Dulwich's path-element validator accepts tree entries with filenames containing bytes that Windows interprets as structural path syntax, such as backslashes (`\`), NTFS alternate-data-stream markers (`:`), and NTFS 8.3 short-name aliases (`git~<digits>`). This allows an attacker to craft malicious Git repositories that, when cloned or checked out on Windows, can write files to arbitrary locations, including inside the `.git` directory. If a file is planted as a Git hook (e.g., `.git\hooks\pre-commit.exe`), it can lead to remote code execution when a user commits changes. POSIX systems are not directly exploitable, but can propagate malicious trees to Windows.

## Attack Chain

1. An attacker crafts a malicious Git repository containing a tree entry with a filename including a backslash (e.g., `.git\hooks\pre-commit.exe`).
2. The attacker hosts the malicious Git repository on a publicly accessible server.
3. A victim user clones the malicious repository using Dulwich on a Windows system (e.g., using `dulwich.porcelain.clone`).
4. Dulwich's path-element validator incorrectly processes the backslash in the filename.
5. The malicious file is written to the `.git\hooks` directory within the victim's local repository, creating the directory structure `.git/hooks/pre-commit.exe`.
6. The victim user attempts to commit changes to the repository using Git.
7. Git executes the planted hook script (`.git/hooks/pre-commit.exe`).
8. The attacker achieves arbitrary code execution in the context of the victim user on the Windows system.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve arbitrary file write and remote code execution on vulnerable Windows systems. This can lead to complete system compromise, data theft, and further lateral movement within the victim's network. The scope of impact depends on the number of developers and systems using affected Dulwich versions and cloning untrusted repositories.

## Recommendation

- Upgrade Dulwich to version 1.2.5 or later to patch CVE-2026-42305.
- Deploy the Sigma rule "Detect Dulwich Git Hook Write via Malicious Filename" to detect attempts to write Git hooks with suspicious filenames.
- Block the use of affected Dulwich versions in your environment until they are patched.
- Audit existing Git repositories for malicious tree entries that may have been introduced through vulnerable Dulwich versions.
