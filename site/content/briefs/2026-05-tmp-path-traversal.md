---
title: tmp NPM Package Path Traversal Vulnerability (CVE-2026-44705)
slug: 2026-05-tmp-path-traversal
description: The tmp npm package contains a path traversal vulnerability (CVE-2026-44705) that allows writing files outside the intended temporary directory when untrusted data flows into the `prefix`, `postfix`, or `dir` options, leading to arbitrary file creation.
date: "2026-05-27T00:36:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path traversal
  - npm package
  - tmp
vendors:
  - npm
products:
  - tmp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://github.com/advisories/GHSA-ph9p-34f9-6g65
  - CVE-2026-44705
rules:
  - title: Detect Suspicious tmp NPM Package Path Traversal via Prefix/Postfix
    description: Detects CVE-2026-44705 exploitation — Path traversal attempts in command lines invoking tmp.file with suspicious prefix or postfix options.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious tmp NPM Package Path Traversal via Absolute Dir
    description: Detects CVE-2026-44705 exploitation — tmp.file or tmp.dir being called with an absolute path specified via the dir argument.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `tmp` npm package is vulnerable to path traversal due to insufficient input sanitization in its file and directory creation functions. By manipulating the `prefix`, `postfix`, or `dir` options, an attacker can write files to arbitrary locations on the file system. This is achieved by including traversal sequences (e.g., `../`) or absolute paths in these options, bypassing the intended temporary directory. The vulnerability affects applications that pass user-controlled data to `tmp`'s file/directory creation functions without proper validation, allowing an attacker to create or overwrite files with the privileges of the running process. This can lead to web application configuration poisoning, cache poisoning, or other security bypasses. The affected versions are all versions prior to the fix. This was reported by Mapta / BugBunny_ai.

## Attack Chain

1. An attacker crafts malicious input containing path traversal sequences (e.g., `../`) within the `prefix`, `postfix`, or `dir` options of the `tmp` package's functions.
2. The application, without proper sanitization, passes this attacker-controlled input to the `tmp.file()` or `tmp.dir()` functions.
3. The `tmp` package constructs a file path by concatenating the `tmpdir`, `dir`, `prefix`, and `postfix` options.
4. The `path.join()` function normalizes the path, resolving the traversal sequences and potentially allowing the final path to escape the intended temporary directory.
5. The `tmp` package attempts to create a file or directory at the constructed path using `fs.writeFileSync()` or similar functions.
6. Due to the path traversal, the file or directory is created outside the intended temporary directory, potentially in a sensitive location.
7. Depending on the attacker's chosen location, they can achieve effects such as web application configuration poisoning or cache poisoning.
8. The attacker gains unauthorized access or control over the application or system.

## Impact

Successful exploitation allows attackers to create files outside the intended temporary directories, leading to arbitrary file creation with the privileges of the running process. This can result in various attack scenarios, including web application configuration poisoning, cache poisoning, build pipeline compromise, container escape attempts, and multi-tenant service bypass. For instance, an attacker could overwrite application configuration files, inject malicious code into cached content, or gain access to sensitive data. The vulnerability has a CVSS v3.1 score of 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L).

## Recommendation

*   Implement input validation and sanitization for the `prefix`, `postfix`, and `dir` options before passing them to the `tmp.file()` or `tmp.dir()` functions, as described in the Remediation section of this brief.
*   Monitor for file creation events outside expected temporary directories using file system monitoring tools, as demonstrated in the Detection and Monitoring section of this brief.
*   Deploy the Sigma rule "Detect Suspicious tmp NPM Package Path Traversal via Prefix/Postfix" to identify exploitation attempts by detecting path traversal sequences in process command lines.
*   Apply the safe TmpFile workaround described in the Remediation section to strip out unsafe characters.
