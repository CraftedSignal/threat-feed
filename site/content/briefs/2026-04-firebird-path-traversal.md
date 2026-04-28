---
title: Firebird Path Traversal Vulnerability Leads to Code Execution (CVE-2026-40342)
slug: 2026-04-firebird-path-traversal
description: An authenticated user with CREATE FUNCTION privileges can exploit a path traversal vulnerability in Firebird versions prior to 5.0.4, 4.0.7, and 3.0.14, to load an arbitrary shared library leading to code execution as the server's OS account.
date: "2026-04-17T20:16:35Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - firebird
  - path-traversal
  - code-execution
  - cve-2026-40342
  - database
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Indirect Command Execution
cves:
  - id: CVE-2026-40342
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40342
rules:
  - title: Detect Firebird Create Function Path Traversal
    description: Detects CREATE FUNCTION statements in Firebird with ENGINE names containing path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - database
      - firebird
  - title: Detect Shared Library Load from Suspicious Path
    description: Detects loading of shared libraries from /tmp or other suspicious paths, which may indicate exploitation of CVE-2026-40342
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Firebird, an open-source relational database management system, is vulnerable to a path traversal flaw (CVE-2026-40342) in versions prior to 5.0.4, 4.0.7, and 3.0.14. This vulnerability resides within the external engine plugin loader. The loader concatenates a user-supplied engine name into a filesystem path without proper sanitization, leaving it open to path traversal attacks. An authenticated user with `CREATE FUNCTION` privileges can craft a malicious `ENGINE` name containing path separators and `..` components. This allows them to load an arbitrary shared library from anywhere on the filesystem. The library's initialization code executes immediately upon loading, before Firebird can validate the module, effectively granting code execution under the security context of the server's operating system account. Upgrading to versions 5.0.4, 4.0.7, or 3.0.14 resolves this issue.

## Attack Chain

1.  Attacker authenticates to the Firebird database server with an account possessing `CREATE FUNCTION` privileges.
2.  Attacker crafts a malicious `ENGINE` name that includes path traversal sequences (e.g., `../../../../`).
3.  The attacker uses the crafted `ENGINE` name in a `CREATE FUNCTION` statement, specifying a path to an arbitrary shared library on the filesystem. For example, `CREATE FUNCTION evil_func RETURNS INTEGER ENGINE '/path/to/evil/../../../../tmp/evil.so'`.
4.  The Firebird server's plugin loader concatenates the provided `ENGINE` name into a filesystem path without proper validation.
5.  The Firebird server attempts to load the shared library from the attacker-controlled path, effectively bypassing intended access controls.
6.  The operating system loads the shared library into the Firebird server's process.
7.  The shared library's initialization code executes immediately, granting the attacker arbitrary code execution within the context of the Firebird server process.
8.  The attacker gains control of the Firebird server's OS account, potentially leading to data exfiltration, system compromise, or denial of service.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the Firebird server with the privileges of the operating system account running the Firebird service. This can lead to full system compromise, including data exfiltration, modification, or destruction. Given the high CVSS score of 9.9, this vulnerability poses a critical risk to organizations using vulnerable Firebird versions. The impact could range from complete database compromise to lateral movement within the network, depending on the privileges of the Firebird service account.

## Recommendation

*   Upgrade Firebird servers to versions 5.0.4, 4.0.7, or 3.0.14 to patch CVE-2026-40342.
*   Monitor Firebird server logs for `CREATE FUNCTION` statements with suspicious `ENGINE` names containing path traversal sequences, and deploy the Sigma rule `Detect Firebird Create Function Path Traversal` to your SIEM.
*   Implement strict access controls to limit `CREATE FUNCTION` privileges to only authorized users, and enable audit logging on all Firebird database servers to monitor user activity.
