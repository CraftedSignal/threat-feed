---
title: WWBN AVideo Unauthenticated Path Traversal Vulnerability (CVE-2026-41058)
slug: 2026-04-avideo-path-traversal
description: WWBN AVideo versions 29.0 and below contain a path traversal vulnerability (CVE-2026-41058) in the CloneSite functionality, allowing unauthenticated attackers to delete arbitrary files via manipulation of the `deleteDump` parameter.
date: "2026-04-22T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - path traversal
  - cve-2026-41058
  - avideo
  - webserver
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-41058
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41058
  - https://github.com/WWBN/AVideo/commit/3c729717c26f160014a5c86b0b6accdbd613e7b2
rules:
  - title: Detect AVideo Path Traversal Attempt
    description: Detects potential path traversal attempts targeting the AVideo CloneSite functionality by looking for '..' sequences in the deleteDump parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo Arbitrary File Deletion via Path Traversal
    description: Detects potential arbitrary file deletion attempts targeting the AVideo CloneSite functionality by looking for 'unlink' and file paths.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo is an open-source video platform. Versions 29.0 and below are vulnerable to a path traversal vulnerability (CVE-2026-41058) due to an incomplete fix for the `deleteDump` parameter in the CloneSite functionality. This vulnerability allows unauthenticated attackers to delete arbitrary files on the server by injecting `../../` sequences into the GET request. The vulnerability was reported on April 21, 2026, and a fix is available in commit 3c729717c26f160014a5c86b0b6accdbd613e7b2. Successful exploitation allows attackers to potentially disrupt service, delete sensitive data, or escalate privileges depending on the file permissions.

## Attack Chain

1.  The attacker identifies an AVideo instance running version 29.0 or below.
2.  The attacker crafts a malicious HTTP GET request targeting the CloneSite functionality.
3.  The attacker injects a path traversal sequence (e.g., `../../`) into the `deleteDump` parameter of the GET request.
4.  The AVideo application fails to properly sanitize the `deleteDump` parameter.
5.  The `unlink()` function is called with the attacker-controlled path, allowing deletion of arbitrary files.
6.  The attacker uses the vulnerability to delete critical system files or configuration files.
7.  The application or server becomes unstable or inoperable.

## Impact

Successful exploitation of CVE-2026-41058 allows unauthenticated attackers to delete arbitrary files on the AVideo server. This can lead to denial of service, data loss, or potential privilege escalation if critical system files are deleted. The vulnerability affects all AVideo instances running version 29.0 or below, potentially impacting a large number of users and organizations relying on the platform.

## Recommendation

*   Upgrade AVideo instances to a version containing the fix from commit 3c729717c26f160014a5c86b0b6accdbd613e7b2 to address CVE-2026-41058.
*   Deploy the Sigma rule `Detect AVideo Path Traversal Attempt` to identify exploitation attempts in web server logs.
*   Implement web application firewall (WAF) rules to block requests containing path traversal sequences in the `deleteDump` parameter.
*   Monitor web server logs for suspicious activity related to the CloneSite functionality and the `deleteDump` parameter.
