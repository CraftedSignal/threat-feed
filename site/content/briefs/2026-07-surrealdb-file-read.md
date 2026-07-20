---
title: SurrealDB Arbitrary File Read Vulnerability CVE-2026-63739
slug: 2026-07-surrealdb-file-read
description: SurrealDB versions prior to 3.1.5 contain an arbitrary file read vulnerability (CVE-2026-63739) within the DEFINE ANALYZER mapper filter that allows authenticated database users with EDITOR or OWNER roles to read arbitrary files from the server filesystem by injecting file paths into query error messages, especially when the SURREAL_FILE_ALLOWLIST is unconfigured.
date: "2026-07-20T12:25:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - arbitrary-file-read
  - database
  - cve
vendors:
  - SurrealDB
products:
  - SurrealDB (before 3.1.5)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: allows database users with EDITOR or OWNER roles to read files accessible to the SurrealDB process. Attackers can specify arbitrary file paths in the mapper filter and retrieve file contents through query error messages
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers can specify arbitrary file paths in the mapper filter and retrieve file contents through query error messages
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: allows database users with EDITOR or OWNER roles to read files
    confidence_band: high
cves:
  - id: CVE-2026-63739
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63739
  - https://github.com/surrealdb/surrealdb/security/advisories/GHSA-cc8f-fcx3-gpjr
---

A critical arbitrary file read vulnerability, tracked as CVE-2026-63739, has been identified in SurrealDB versions prior to 3.1.5. This flaw resides within the `DEFINE ANALYZER mapper filter` component of the database. Exploitation requires an attacker to possess existing authenticated access to the SurrealDB instance with either `EDITOR` or `OWNER` roles. By crafting a malicious query that injects arbitrary file paths into the mapper filter, an attacker can coerce the database to disclose the contents of files accessible by the SurrealDB process. This sensitive information is then retrieved through verbose database query error messages, particularly when the `SURREAL_FILE_ALLOWLIST` security control is not configured or is empty. This vulnerability poses a significant risk for data exfiltration and unauthorized information disclosure.

## Attack Chain

1. An attacker gains authenticated access to a vulnerable SurrealDB instance, holding either an `EDITOR` or `OWNER` role.
2. The attacker crafts a database query using the `DEFINE ANALYZER` statement.
3. Within the `mapper filter` component of the `DEFINE ANALYZER` statement, the attacker injects a relative or absolute path to a target file on the server's filesystem (e.g., `/etc/passwd` or `C:\Windows\System32\drivers\etc\hosts`).
4. The SurrealDB server processes this malformed query.
5. During the processing, if the `SURREAL_FILE_ALLOWLIST` is unconfigured or empty, the database attempts to access the specified arbitrary file path.
6. The database generates an error message that inadvertently includes the full content of the targeted file.
7. The attacker receives this detailed error message as part of the query response, thus exfiltrating the file's contents.
8. This allows the attacker to read sensitive configuration files, credentials, or other critical data from the host system.

## Impact

The successful exploitation of CVE-2026-63739 allows an authenticated attacker to read any file accessible by the SurrealDB process on the host system. This can lead to the disclosure of highly sensitive information, such as system configuration files, database credentials, private keys, or other proprietary data, with a CVSS v3.1 base score of 7.7 (High). Such information could then be used for further privilege escalation, lateral movement, or complete system compromise. The specific damage depends on the sensitivity of the files readable by the SurrealDB process and the overall security posture of the environment.

## Recommendation

* Upgrade SurrealDB instances to version 3.1.5 or newer immediately to patch the CVE-2026-63739 vulnerability.
* Configure the `SURREAL_FILE_ALLOWLIST` security setting in SurrealDB to explicitly define and restrict which file paths the database process is permitted to access.
* Implement strict principle of least privilege for all database users; ensure that users with `EDITOR` or `OWNER` roles only have necessary permissions and access.
