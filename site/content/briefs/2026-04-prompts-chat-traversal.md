---
title: prompts.chat Path Traversal Vulnerability (CVE-2026-22661)
slug: 2026-04-prompts-chat-traversal
description: A path traversal vulnerability exists in prompts.chat prior to commit 0f8d4c3, allowing attackers to write arbitrary files to the client system by crafting malicious ZIP archives with unsanitized filenames.
date: "2026-04-04T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - file-write
  - code-execution
  - cve-2026-22661
  - prompts.chat
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-22661
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22661
rules:
  - title: Detect Path Traversal in Filenames via Web Logs
    description: Detects attempts to exploit path traversal vulnerabilities by identifying '..' sequences in filenames within HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Path Traversal in POST requests via Web Logs
    description: 'Detects attempts to exploit path traversal vulnerabilities by identifying ''..'' sequences in filenames within HTTP POST requests. '
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

prompts.chat, a software application, is vulnerable to a path traversal attack (CVE-2026-22661) in versions prior to commit 0f8d4c3. This vulnerability stems from insufficient server-side validation of filenames within skill file archives. A remote attacker can exploit this by crafting malicious ZIP archives that contain filenames with path traversal sequences (e.g., ../). When a vulnerable prompts.chat instance extracts these archives, the lack of proper sanitization allows the attacker to write files to arbitrary locations on the file system, potentially overwriting critical system files and achieving arbitrary code execution. This poses a significant risk to system integrity and confidentiality.

## Attack Chain

1. The attacker crafts a malicious ZIP archive containing a specially crafted skill file.
2. The filenames within the ZIP archive include path traversal sequences such as `../`.
3. The attacker uploads the malicious ZIP archive to the prompts.chat application.
4. prompts.chat processes the uploaded ZIP archive without properly sanitizing the filenames.
5. The application extracts the contents of the ZIP archive, writing files to locations specified in the malicious filenames.
6. Path traversal sequences in the filenames allow the attacker to write files outside the intended extraction directory.
7. The attacker overwrites shell initialization files (e.g., `.bashrc`, `.profile`, `.bash_profile`) or other executable files.
8. When a user logs in or a new shell is spawned, the overwritten initialization file executes malicious code, granting the attacker arbitrary code execution on the system.

## Impact

Successful exploitation of CVE-2026-22661 allows an attacker to write arbitrary files to the client system, leading to potential overwrite of sensitive system files and arbitrary code execution. The vulnerability affects systems running vulnerable versions of prompts.chat. The impact includes complete compromise of the system, data theft, and further propagation of malicious activities.

## Recommendation

*   Apply the patch by upgrading to commit 0f8d4c3 or later to remediate CVE-2026-22661.
*   Implement server-side filename validation and sanitization to prevent path traversal attacks when handling ZIP archives within prompts.chat.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential exploitation attempts.
*   Monitor web server logs for suspicious requests containing path traversal sequences in filenames as identified by the provided rules.
