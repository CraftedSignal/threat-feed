---
title: SQL Injection in SiYuan Graph Query Endpoint
slug: 2026-09-siyuan-sql-injection
description: SiYuan versions prior to 3.8.4 are vulnerable to a SQL injection vulnerability in the graph query endpoint that allows unauthenticated attackers to exfiltrate database contents.
date: "2026-09-26T15:06:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cves:
  - id: CVE-2026-100644
    cvss: 7.5
---

SiYuan, a local-first note-taking software, contains a critical SQL injection vulnerability identified as CVE-2026-100644. The vulnerability exists within the application's graph query endpoint, where the 'dailyNoteSavePath' parameter is directly concatenated into SQL queries without proper sanitization or escaping. This flaw affects all versions of SiYuan prior to 3.8.4. The vulnerability is particularly dangerous for published sites where authentication is disabled, as it allows unauthenticated attackers to perform remote SQL injection attacks. By leveraging techniques such as UNION SELECT, an attacker can manipulate the underlying database queries to exfiltrate arbitrary rows of data from all notebooks stored within the instance. Given the nature of the application, which often contains sensitive personal or professional information, this vulnerability poses a significant risk to data privacy. Defenders should prioritize patching to version 3.8.4 or higher to remediate this flaw.

## Impact

Successful exploitation of CVE-2026-100644 allows for unauthorized access to the entire contents of a user's notebooks stored within the SiYuan database. This could result in the large-scale exfiltration of sensitive, private, or proprietary information. The impact is highest for users who have enabled the publishing feature without authentication, as these instances are directly reachable by unauthenticated remote attackers.

## Recommendation

* Update SiYuan instances to version 3.8.4 or later immediately to resolve the vulnerable concatenation
