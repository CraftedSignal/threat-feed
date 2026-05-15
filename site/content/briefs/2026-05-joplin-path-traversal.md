---
title: Joplin OneNote Importer Path Traversal Vulnerability (CVE-2026-22810)
slug: 2026-05-joplin-path-traversal
description: A path traversal vulnerability exists in the OneNote importer of Joplin versions 3.5.6 and earlier. By importing a crafted .one file, an attacker can overwrite arbitrary files on the disk, potentially leading to privilege escalation and remote code execution. The vulnerability stems from the lack of sanitization of embedded file names within the OneNote converter, allowing filenames containing directory traversal sequences like `../../`.
date: "2026-05-15T16:29:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - file-overwrite
  - cve-2026-22810
  - joplin
vendors:
  - Joplin
products:
  - Joplin (<= 3.5.6)
affected_os:
  - Fedora Linux 43
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-gcmj-c9gg-9vh6
  - https://github.com/laurent22/joplin/blob/af5108d70233b1db9410346958c1587cf7c1b16d/packages/onenote-converter/renderer/src/page/embedded_file.rs#L13-L16
  - https://github.com/laurent22/joplin/blob/af5108d70233b1db9410346958c1587cf7c1b16d/packages/onenote-converter/renderer/src/page/embedded_file.rs#L56-L64
  - https://github.com/laurent22/joplin/blob/4d7fa5972fe2986eae14cbf3a2801835cbe1384e/packages/onenote-converter/src/page/embedded_file.rs#L14
  - https://github.com/laurent22/joplin/commit/791668455e1aae50501ff57ea4783b3fba9d377c
  - https://github.com/msiemens/one2html/commit/948d65cdca5bb35d776b8b235ec05ff15249fd41
rules:
  - title: Detect CVE-2026-22810 Path Traversal File Creation
    description: Detects CVE-2026-22810 exploitation — Creation of files with path traversal sequences (../) in their names, indicating a potential path traversal vulnerability exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1566
    data_sources:
      - file_event
      - linux
  - title: Detect CVE-2026-22810 Path Traversal - Suspicious Log File Overwrite
    description: Detects CVE-2026-22810 exploitation — Overwriting of common log files with non-log file extensions.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1566
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Joplin, a popular open-source note-taking application, is vulnerable to a path traversal attack (CVE-2026-22810) within its OneNote import functionality. This flaw affects Joplin versions 3.5.6 and earlier. The vulnerability lies in the `@joplin/onenote-converter` npm package, specifically due to the insufficient sanitization of filenames extracted from OneNote's `.one` files. By crafting a malicious `.one` file containing embedded files with names incorporating directory traversal sequences (e.g., `../../`), an attacker can control the write path of extracted files during the import process. This can lead to overwriting arbitrary files on the system where Joplin is running. The vulnerability was introduced around Joplin 3.2.2 when the OneNote importer was first introduced, and was identified and reported in May 2026.

## Attack Chain

1. An attacker crafts a malicious `.one` file. This file contains specially named embedded files, with the filenames including path traversal sequences like `../../`.
2. The victim imports the malicious `.one` file into Joplin (versions 3.5.6 or earlier).
3. Joplin's OneNote importer (`@joplin/onenote-converter`) processes the `.one` file.
4. The importer extracts embedded files without proper sanitization of the filenames.
5. The `embedded_file.rs` component of the importer constructs a file path based on the extracted filename.
6. The path traversal sequences in the filename are interpreted, allowing the write operation to escape the intended directory.
7. The extracted file is written to an arbitrary location on the file system, overwriting the existing file.
8. The attacker achieves arbitrary file overwrite, potentially leading to code execution if a critical system file is targeted (e.g., `.bashrc` or application configuration files).

## Impact

Successful exploitation of this path traversal vulnerability (CVE-2026-22810) allows an attacker to overwrite arbitrary files on the victim's system. This can lead to a variety of consequences, including denial of service, privilege escalation, and potentially remote code execution. The provided proof-of-concept overwrites Joplin's `log.txt` file, but more sensitive files such as `.bashrc` on Linux systems can be targeted. All users of Joplin versions 3.5.6 and earlier who utilize the OneNote import functionality are vulnerable.

## Recommendation

*   Upgrade Joplin to version 3.5.7 or later to incorporate the patch for CVE-2026-22810 ([https://github.com/laurent22/joplin/commit/791668455e1aae50501ff57ea4783b3fba9d377c](https://github.com/laurent22/joplin/commit/791668455e1aae50501ff57ea4783b3fba9d377c)).
*   Deploy the following Sigma rule to detect potential exploitation attempts involving path traversal sequences in file creation events.
