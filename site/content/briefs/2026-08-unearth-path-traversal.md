---
title: Path Traversal Vulnerability in unearth Library
slug: 2026-08-unearth-path-traversal
description: The unearth library version 0.18.2 and earlier contains a path traversal vulnerability in the is_within_directory function that permits arbitrary file writes via malicious archives.
date: "2026-08-10T21:40:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - vulnerability
  - supply-chain
products:
  - unearth (<= 0.18.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can supply malicious tar archives with symlink members or traversal sequences to write files to arbitrary filesystem locations accessible to the process.
    confidence_band: med
cves:
  - id: CVE-2026-73030
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73030
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Update unearth library to version > 0.18.2
      owner: Application Security
      due: 48h
      evidence: CVE-2026-73030 fixed in commit 6c78164
  mitigation_plan:
    - priority: short_term
      action: Restrict file system write permissions for processes utilizing unearth
      owner: IT Operations
      addresses: CVE-2026-73030
      evidence: Arbitrary filesystem write capability of vulnerability
---

The unearth library, used for utility operations in Python environments, contains a critical path traversal vulnerability (CVE-2026-73030) in its `is_within_directory` function. The vulnerability stems from the library's failure to normalize file paths before performing directory containment validation. By exploiting this flaw, an attacker can supply specially crafted tar archives containing directory traversal sequences (e.g., `../`) or malicious symlinks to break out of the target extraction directory. Successful exploitation allows the attacker to write files to arbitrary locations on the filesystem, restricted only by the permissions of the process executing the unearth library. This vulnerability impacts all versions up to 0.18.2. Users are advised to update to a patched version, as the fix was implemented in commit 6c78164. Given the nature of libraries like unearth, this could affect a wide range of downstream applications that process external archives.

## Impact

The vulnerability carries a CVSS v3.1 base score of 8.1, indicating a high impact on system integrity and security. If exploited, an attacker could achieve arbitrary file write, potentially leading to remote code execution by overwriting critical system binaries, configuration files, or startup scripts, depending on the context in which the library is utilized within an application.

## Recommendation

- Identify all instances of the unearth library within the environment and inventory applications that utilize version 0.18.2 or earlier.
- Upgrade the unearth dependency to a version containing the fix for CVE-2026-73030 (as implemented in commit 6c78164).
- Implement file integrity monitoring (FIM) on directories where third-party archives are extracted to detect anomalous file creation patterns.
- Run processes that utilize unearth with the principle of least privilege, ensuring the service user has minimal write access to the filesystem.
