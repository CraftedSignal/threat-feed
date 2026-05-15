---
title: SimpleSAMLphp casserver FileSystemTicketStore Path Traversal Vulnerability
slug: 2026-05-simplesamlphp-traversal
description: A path traversal vulnerability in SimpleSAMLphp's casserver module allows remote attackers to read and potentially delete arbitrary files outside the ticket directory by manipulating the ticket parameter in CAS validation requests, impacting confidentiality and integrity.
date: "2026-05-15T18:10:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - file-deletion
  - simplesamlphp
vendors:
  - composer
products:
  - simplesamlphp/simplesamlphp-module-casserver <= 7.0.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-jrrg-99xh-5j2q
rules:
  - title: Detect SimpleSAMLphp FileSystemTicketStore Path Traversal Attempt
    description: Detects CVE-2026-46491 exploitation — attempts to exploit path traversal in SimpleSAMLphp FileSystemTicketStore by looking for 'ticket' or 'pgt' parameters containing '..'.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SimpleSAMLphp FileSystemTicketStore Arbitrary File Access
    description: Detects attempts to access files outside the intended ticket directory in SimpleSAMLphp FileSystemTicketStore by looking for 'ticket' or 'pgt' parameters containing '../' followed by a file extension.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A path traversal vulnerability exists within the `simplesamlphp-module-casserver` module, specifically affecting deployments that utilize the `FileSystemTicketStore`. This vulnerability, identified as CVE-2026-46491, arises from the direct concatenation of the configured ticket directory with attacker-controlled ticket identifiers received via the `ticket` or `pgt` query parameters in public CAS validation/proxy endpoints. By injecting path traversal sequences (e.g., `../target.serialized`) into these parameters, attackers can read and unserialize arbitrary files outside the designated ticket directory. Furthermore, the CAS 1.0 validation flow can lead to the deletion of attacker-specified files if the PHP process has sufficient permissions and the file contents can be unserialized into a compatible type. This issue impacts versions of `composer/simplesamlphp/simplesamlphp-module-casserver` up to and including 7.0.2.

## Attack Chain

1.  The attacker identifies a SimpleSAMLphp instance with the casserver module enabled and configured to use FileSystemTicketStore.
2.  The attacker crafts a malicious CAS validation/proxy request containing a `ticket` or `pgt` parameter with a path traversal sequence (e.g., `../target.serialized`).
3.  The SimpleSAMLphp application receives the request and concatenates the attacker-controlled `ticket` parameter with the configured ticket directory.
4.  The application attempts to read the file at the constructed path using `getTicket()`. Due to the path traversal, the file accessed is outside the intended ticket directory.
5.  If the file contains valid serialized PHP data, the application unserializes its content.
6.  In the CAS 1.0 validation flow, the application calls `deleteTicket()` with the same attacker-controlled path.
7.  If the PHP process has sufficient permissions and the unserialized content meets certain criteria (e.g., an array or null), the target file is deleted.
8.  The attacker achieves unauthorized file read and potentially deletion, impacting system integrity and confidentiality.

## Impact

Successful exploitation of this vulnerability (CVE-2026-46491) allows remote attackers to bypass intended file access restrictions. Confirmed impacts include the ability to read and unserialize arbitrary files outside the designated ticket cache, potentially exposing sensitive data. Furthermore, under specific conditions within the CAS 1.0 validation flow, attackers can delete files outside the ticket cache, leading to denial-of-service or data loss scenarios. The severity of file deletion depends on the filesystem permissions of the PHP process and the content of the targeted file. This could potentially lead to destruction of CAS tickets, serialized SimpleSAMLphp runtime/cache files, or other writable files whose contents can be unserialized into a value accepted by the `?array` return type.

## Recommendation

*   Upgrade the `composer/simplesamlphp/simplesamlphp-module-casserver` package to a version greater than 7.0.2 to remediate CVE-2026-46491.
*   Implement input validation and sanitization on the `ticket` and `pgt` parameters to prevent path traversal attacks.
*   Deploy the Sigma rule "Detect SimpleSAMLphp FileSystemTicketStore Path Traversal Attempt" to identify potential exploitation attempts.
*   Review and restrict the filesystem permissions of the PHP process to minimize the impact of potential file deletion.
