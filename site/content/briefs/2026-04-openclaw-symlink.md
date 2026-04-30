---
title: OpenClaw Symlink Vulnerability in SSH Sandbox Tar Upload (CVE-2026-41364)
slug: 2026-04-openclaw-symlink
description: OpenClaw before 2026.3.31 contains a symlink following vulnerability in SSH sandbox tar upload that allows remote attackers to write arbitrary files by uploading a malicious tar archive containing symlinks, leading to arbitrary file write on the remote host.
date: "2026-04-28T00:16:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - symlink
  - file-write
  - sandbox-escape
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41364
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41364
  - https://github.com/openclaw/openclaw/commit/3d5af14984ac1976c747a8e11581d697bd0829dc
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-fv94-qvg8-xqpw
  - https://www.vulncheck.com/advisories/openclaw-arbitrary-file-write-via-symlink-following-in-ssh-sandbox-tar-upload
rules:
  - title: Detect Suspicious Tar Archive Upload with Symlinks
    description: Detects the upload of tar archives containing symlinks, which can be indicative of a sandbox escape attempt via CVE-2026-41364 in OpenClaw.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious File Overwrite via Tar Extraction
    description: Detects the modification of system files outside of normal user directories during tar extraction, indicating potential exploitation of CVE-2026-41364.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw versions before 2026.3.31 are vulnerable to a symlink following issue within the SSH sandbox tar upload functionality. This vulnerability, identified as CVE-2026-41364, allows a remote attacker with the ability to upload tar archives to the OpenClaw instance to potentially escape the intended sandbox environment. By crafting a malicious tar archive containing carefully constructed symbolic links, an attacker can overwrite arbitrary files on the remote host, leading to a compromise of the system's integrity. This vulnerability was reported and patched in version 2026.3.31. Defenders need to ensure they are running patched versions to mitigate the risk of exploitation.

## Attack Chain

1. Attacker authenticates to the OpenClaw instance via SSH, gaining access to the restricted sandbox environment.
2. Attacker crafts a malicious tar archive containing symbolic links pointing outside the intended sandbox directory. These symlinks are designed to target specific files or directories on the host system that the attacker wishes to overwrite.
3. Attacker uploads the malicious tar archive to the OpenClaw instance using the SSH sandbox tar upload functionality.
4. OpenClaw extracts the contents of the uploaded tar archive without properly validating or restricting the target paths of the symbolic links.
5. During extraction, the symbolic links are followed, causing files to be written outside the intended sandbox directory.
6. The attacker overwrites arbitrary files on the remote host with attacker-controlled content.
7. The attacker achieves arbitrary code execution or persistence by overwriting critical system files or configuration files.
8. The attacker escalates privileges by modifying binaries used by privileged users.

## Impact

Successful exploitation of this vulnerability allows a remote attacker with low privileges to write arbitrary files on the OpenClaw server. This can lead to a variety of impacts, including arbitrary code execution, privilege escalation, and denial of service. An attacker could potentially gain complete control over the OpenClaw server by overwriting critical system files. Given the potential for complete system compromise, this vulnerability poses a significant risk to organizations using affected versions of OpenClaw.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.31 or later to patch CVE-2026-41364.
*   Deploy the Sigma rule "Detect Suspicious Tar Archive Upload with Symlinks" to detect attempts to upload malicious tar archives containing symbolic links.
*   Monitor SSH logs for suspicious activity related to tar archive uploads to the OpenClaw instance.
