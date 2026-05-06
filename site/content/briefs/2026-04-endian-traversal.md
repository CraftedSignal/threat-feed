---
title: Endian Firewall Arbitrary File Deletion via Path Traversal (CVE-2026-34790)
slug: 2026-04-endian-traversal
description: Endian Firewall versions 3.3.25 and prior allow authenticated users to delete arbitrary files due to a path traversal vulnerability in the `remove ARCHIVE` parameter of the `/cgi-bin/backup.cgi` script, leading to unauthorized file system modification.
date: "2026-04-02T15:16:42Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - path-traversal
  - file-deletion
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials on Shared Network Drive
cves:
  - id: CVE-2026-34790
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34790
  - https://help.endian.com/hc/en-us/sections/360004371358-Community
  - https://www.vulncheck.com/advisories/endian-firewall-cgi-bin-backup-cgi-remove-archive-directory-traversal
rules:
  - title: Detect Endian Firewall Path Traversal Attempt
    description: Detects potential path traversal attempts in the remove ARCHIVE parameter of /cgi-bin/backup.cgi on Endian Firewall.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Endian Firewall Unlink Call with Traversal
    description: Detects system unlink calls when attacker attempts a path traversal attack.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Endian Firewall, a security-focused Linux distribution designed for gateway security, is vulnerable to a path traversal attack. Specifically, versions 3.3.25 and earlier are affected by CVE-2026-34790. An authenticated user, with low-level privileges, can exploit this vulnerability to delete arbitrary files on the system. The flaw resides in the `/cgi-bin/backup.cgi` script where the `remove ARCHIVE` parameter is not properly sanitized. This allows an attacker to inject directory traversal sequences (e.g., `../`) into the file path, bypassing intended restrictions. This can lead to deletion of sensitive files, potentially disrupting system operations or facilitating further malicious activities. The vulnerability was reported in April 2026.

## Attack Chain

1. An attacker authenticates to the Endian Firewall web interface.
2. The attacker crafts a malicious HTTP request targeting `/cgi-bin/backup.cgi`.
3. The request includes the `remove ARCHIVE` parameter with a payload containing directory traversal sequences (e.g., `../../../../etc/shadow`).
4. The `/cgi-bin/backup.cgi` script receives the request and constructs a file path using the unsanitized `remove ARCHIVE` parameter.
5. The script calls the `unlink()` function with the attacker-controlled file path.
6. The `unlink()` function deletes the file specified by the manipulated path.
7. The attacker repeats this process to delete other critical system files.
8. This can lead to a denial-of-service condition, data loss, or the potential for further system compromise.

## Impact

Successful exploitation of this vulnerability allows an attacker to delete arbitrary files on the Endian Firewall system. This can result in a denial-of-service (DoS) condition if critical system files are removed. An attacker may target configuration files, logs, or even binaries, leading to system instability or the disabling of security features. The number of potential victims is dependent on the number of Endian Firewall deployments running vulnerable versions (3.3.25 and prior). Given that Endian Firewall is often used in small to medium-sized businesses, the impact could range from disruption of network services to potential data breaches, depending on the specific files targeted.

## Recommendation

*   Apply available patches or upgrade to a version of Endian Firewall that addresses CVE-2026-34790 to remediate the vulnerability.
*   Monitor web server logs for requests to `/cgi-bin/backup.cgi` containing directory traversal sequences (e.g., `../`, `..\\`) in the `remove ARCHIVE` parameter using the provided Sigma rule "Detect Endian Firewall Path Traversal Attempt".
*   Implement input validation and sanitization on all user-supplied input, especially within CGI scripts like `/cgi-bin/backup.cgi`, to prevent path traversal attacks.
*   Restrict access to the Endian Firewall web interface to trusted networks or users and enforce strong authentication measures.
*   Regularly back up the Endian Firewall configuration and critical system files to mitigate the impact of potential data loss due to successful exploitation.
