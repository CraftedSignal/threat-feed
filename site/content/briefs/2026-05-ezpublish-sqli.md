---
title: SQL Injection Vulnerability in ezsystems ezpublish-legacy dfscleanup
slug: 2026-05-ezpublish-sqli
description: A SQL injection vulnerability exists in ezpublish-legacy, specifically in the dfscleanup.php script and the `_getFileList` function of the `eZDFSFileHandlerMySQLiBackend` class, allowing an attacker with local shell access to potentially expose sensitive data such as user credentials.
date: "2026-05-29T19:12:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - vulnerability
vendors:
  - ezsystems
products:
  - ezpublish-legacy (= 2019.03)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-xg9x-h37w-h3r3
  - https://github.com/Goaterino/ezpublish-legacy-lab/blob/main/SQL%20injection%20and%20arbitrary%20file%20deletion%20in%20dfscleanup.md
rules:
  - title: Detect dfscleanup.php Execution with SQL Injection Attempts
    description: Detects CVE-2026-38739 exploitation — Execution of dfscleanup.php with command-line arguments indicative of SQL injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A SQL injection vulnerability exists within the `ezsystems/ezpublish-legacy` application, specifically within the `dfscleanup.php` script and the `_getFileList` function of the `eZDFSFileHandlerMySQLiBackend` class (located at `kernel/private/classes/clusterfilehandlers/dfsbackends/mysqli.php`). This vulnerability allows an attacker with local shell access and sufficient privileges to run `dfscleanup.php` to perform a union-based SQL injection against the eZ Publish MySQL database. The identified vulnerability affects the 2019.03 branch of the software, and it may also affect other branches. However, it's important to note that all tags and branches in this repository are past their end of life, and therefore, this vulnerability will not be patched. This poses a risk to organizations still using the affected software, potentially leading to the exposure of sensitive data, including user credentials. The vulnerability is tracked as CVE-2026-38739.

## Attack Chain

1.  Attacker gains local shell access to the server hosting the vulnerable `ezpublish-legacy` application.
2.  Attacker obtains sufficient privileges to execute the `dfscleanup.php` script.
3.  Attacker crafts a malicious input to the `dfscleanup.php` script, exploiting the SQL injection vulnerability in the `_getFileList` function of the `eZDFSFileHandlerMySQLiBackend` class.
4.  The `dfscleanup.php` script executes the crafted SQL query against the eZ Publish MySQL database.
5.  The SQL injection vulnerability allows the attacker to perform a union-based SQL injection, retrieving data beyond what is normally accessible.
6.  Attacker extracts sensitive data from the database, such as user credentials and other confidential information.
7.  Attacker uses the extracted credentials to escalate privileges within the application or gain access to other systems.
8.  Attacker exfiltrates the sensitive data, potentially causing further damage to the organization.

## Impact

Successful exploitation of this SQL injection vulnerability could lead to the exposure of sensitive data stored within the eZ Publish MySQL database, including user credentials, configuration details, and other confidential information. While the specific number of victims is unknown, any organization still running the affected `ezpublish-legacy` version (2019.03 or potentially other branches) is at risk. If an attack succeeds, it could result in data breaches, unauthorized access to systems, and potential reputational damage to the targeted organization.

## Recommendation

*   Since the software is past its end-of-life, patching is not an option. Consider migrating to a supported platform to remediate CVE-2026-38739.
*   Monitor execution of `dfscleanup.php` with command line arguments containing SQL keywords to detect potential exploitation attempts using the provided Sigma rule.
*   Review the report by Advens (https://github.com/Goaterino/ezpublish-legacy-lab/blob/main/SQL%20injection%20and%20arbitrary%20file%20deletion%20in%20dfscleanup.md) for further details on the vulnerability.
