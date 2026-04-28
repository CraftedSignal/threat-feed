---
title: Weblate Path Traversal Vulnerability in ZIP Download Feature (CVE-2026-34242)
slug: 2026-04-weblate-path-traversal
description: Weblate versions before 5.17 are vulnerable to path traversal due to improper verification of downloaded files in the ZIP download feature, potentially allowing attackers to access files outside the intended repository.
date: "2026-04-15T19:16:35Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - weblate
  - path-traversal
  - zip-archive
  - cve-2026-34242
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-34242
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34242
  - https://github.com/WeblateOrg/weblate/commit/5db3a2a2e047ecaab627a8731cd744a30b2f51d3
  - https://github.com/WeblateOrg/weblate/security/advisories/GHSA-hv99-mxm5-q397
rules:
  - title: Detect ZIP Archive Downloads with Suspicious Filenames
    description: Detects downloads of ZIP archives that contain filenames with '..' or other path traversal indicators, which may be indicative of CVE-2026-34242 exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
  - title: Detect Attempted Path Traversal via HTTP Request
    description: Detects HTTP requests containing '..' sequences that may indicate path traversal attempts.
    platform: sigma
    severity: low
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Weblate, a web-based localization tool, has a path traversal vulnerability (CVE-2026-34242) affecting versions prior to 5.17. The vulnerability exists within the ZIP download feature, where the application fails to adequately verify downloaded files. This can allow an attacker to craft a malicious ZIP archive containing symbolic links that, when extracted by a user or the application itself, can lead to files outside of the intended repository being accessed. The vulnerability was reported and patched in version 5.17. Exploitation of this vulnerability requires a user to download and extract a maliciously crafted ZIP file.

## Attack Chain

1.  Attacker identifies a Weblate instance running a version prior to 5.17.
2.  Attacker gains access to a translation project, either legitimately (e.g., as a translator) or illegitimately (e.g., via compromised credentials or another vulnerability).
3.  Attacker crafts a malicious ZIP archive containing symbolic links that point to sensitive files or directories outside the intended Weblate repository (e.g., `/etc/passwd`, application configuration files).
4.  Attacker uploads the malicious ZIP archive to the Weblate project, potentially disguised as a legitimate translation file.
5.  A user (e.g., an administrator or another translator) downloads the ZIP archive using the ZIP download feature.
6.  The user extracts the ZIP archive on their local machine or, if Weblate automatically processes the ZIP, on the server.
7.  The symbolic links within the extracted archive are resolved, potentially allowing access to sensitive files or directories outside the Weblate repository.
8.  Attacker gains unauthorized access to sensitive information, potentially leading to further compromise of the system.

## Impact

Successful exploitation of this path traversal vulnerability (CVE-2026-34242) can allow an attacker to read arbitrary files on the server where Weblate is installed or on a user's machine if the user downloads and extracts the crafted ZIP archive locally. This could lead to the exposure of sensitive information such as application configuration files, database credentials, or even system-level files, depending on the permissions of the user or the Weblate application. The severity is rated as HIGH with a CVSS v3.1 score of 7.7.

## Recommendation

*   Upgrade Weblate to version 5.17 or later to patch CVE-2026-34242 (reference: Overview).
*   Implement file integrity monitoring on Weblate servers to detect unauthorized file access (reference: Attack Chain - step 7).
*   Deploy the Sigma rule to detect ZIP archive downloads containing suspicious filenames that might indicate path traversal attempts (reference: rules).
*   Educate users about the risks of downloading and extracting files from untrusted sources (reference: Overview).
