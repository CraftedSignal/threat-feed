---
title: Apktool Path Traversal Vulnerability (CVE-2026-39973)
slug: 2026-04-apktool-path-traversal
description: A path traversal vulnerability in Apktool versions 3.0.0 and 3.0.1 allows a malicious APK file to write arbitrary files to the filesystem during decoding, potentially leading to remote code execution.
date: "2026-04-21T02:16:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - apktool
  - path-traversal
  - android
  - cve-2026-39973
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1566
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1566
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-39973
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39973
rules:
  - title: Detect Apktool Path Traversal Attempt
    description: Detects potential path traversal attempts when using apktool by monitoring command-line arguments containing '../' sequences.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1566
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Writes via Apktool Vulnerability
    description: Detects file writes to sensitive locations potentially exploited by the Apktool path traversal vulnerability (CVE-2026-39973).
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Apktool, a tool used for reverse engineering Android APK files, is vulnerable to a path traversal issue in versions 3.0.0 and 3.0.1 (CVE-2026-39973). This vulnerability resides within the `brut/androlib/res/decoder/ResFileDecoder.java` component. A maliciously crafted APK can exploit this flaw during standard decoding (`apktool d`) to write arbitrary files to the filesystem. The vulnerability is a security regression introduced by commit e10a045 (PR #4041, December 12, 2025), which inadvertently removed the `BrutIO.sanitizePath()` call, a crucial safeguard against path traversal attacks. By embedding `../` sequences in the `resources.arsc` Type String Pool, attackers can bypass directory restrictions and write files to sensitive locations, such as `~/.ssh/config`, `~/.bashrc`, or Windows Startup folders, ultimately enabling remote code execution. Apktool version 3.0.2 addresses this vulnerability by reintroducing the `BrutIO.sanitizePath()` function in `ResFileDecoder.java`, effectively mitigating the path traversal risk.

## Attack Chain

1. An attacker crafts a malicious Android APK file.
2. The attacker embeds `../` sequences within the `resources.arsc` Type String Pool of the APK.
3. A user attempts to decode the malicious APK file using a vulnerable version of Apktool (3.0.0 or 3.0.1) via the command `apktool d malicious.apk`.
4. During the decoding process, the `ResFileDecoder.java` component processes the `resources.arsc` file.
5. Due to the missing `BrutIO.sanitizePath()` call, the `../` sequences are not sanitized, allowing path traversal.
6. Apktool attempts to write a resource file to a location outside the intended output directory.
7. The resource file is written to an arbitrary location on the filesystem, potentially overwriting critical system files (e.g., `~/.bashrc`, `~/.ssh/config`).
8. If a file like `~/.bashrc` is overwritten, subsequent shell sessions execute malicious code, achieving remote code execution. If a Windows Startup folder is targeted, the code executes on the next reboot.

## Impact

Successful exploitation of this vulnerability allows attackers to write arbitrary files to the filesystem of the machine running Apktool. This can lead to various malicious outcomes, including remote code execution, privilege escalation, and data exfiltration. The impact is particularly severe if Apktool is run with elevated privileges or if sensitive files are overwritten. While specific victim numbers are not available, developers and security researchers who rely on Apktool for APK analysis are at risk.

## Recommendation

*   Upgrade to Apktool version 3.0.2 or later to remediate CVE-2026-39973.
*   Implement file integrity monitoring on sensitive files like `~/.bashrc` and `~/.ssh/config` to detect unauthorized modifications.
*   Enable process monitoring to detect the execution of `apktool d` with suspicious arguments, particularly targeting unexpected output directories.
*   Deploy the Sigma rule "Detect Apktool Path Traversal Attempt" to identify potential exploitation attempts based on command-line arguments.
