---
title: SourceCodester SUP Online Shopping 1.0 SQL Injection Vulnerability (CVE-2026-8129)
slug: 2026-05-sup-online-shopping-sqli
description: A SQL injection vulnerability (CVE-2026-8129) exists in SourceCodester SUP Online Shopping 1.0 due to improper sanitization of the `delwlistid` parameter in `wishlist.php`, allowing a remote attacker to execute arbitrary SQL commands.
date: "2026-05-08T04:16:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - vulnerability
  - webapp
vendors:
  - SourceCodester
products:
  - SUP Online Shopping 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8129
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8129
  - https://github.com/redshadowword-cell/CVE/issues/10
  - https://vuldb.com/vuln/361919
rules:
  - title: Detect SQL Injection Attempt in wishlist.php delwlistid Parameter
    description: Detects potential SQL injection attempts targeting the `delwlistid` parameter in the `wishlist.php` file, indicative of CVE-2026-8129 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - injection
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
  - title: Detect SQL Error Messages in Web Server Logs (Potential Injection Attempt)
    description: Detects SQL error messages in web server logs which can be indicative of SQL injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - injection
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-8129 is a SQL injection vulnerability affecting SourceCodester SUP Online Shopping version 1.0. The vulnerability resides within the `wishlist.php` file, specifically an unknown function that handles the `delwlistid` parameter. A remote attacker can exploit this vulnerability by injecting malicious SQL code into the `delwlistid` parameter, potentially leading to unauthorized data access, modification, or deletion within the application's database. The exploit has been publicly disclosed, increasing the risk of exploitation. Successful exploitation could compromise the entire online shopping platform.

## Attack Chain

1. The attacker identifies a vulnerable instance of SourceCodester SUP Online Shopping 1.0.
2. The attacker crafts a malicious HTTP request targeting the `wishlist.php` file.
3. The crafted request includes a SQL injection payload within the `delwlistid` parameter.
4. The web server processes the request and passes the unsanitized `delwlistid` value to the database query.
5. The injected SQL code is executed within the database context.
6. The attacker can potentially extract sensitive information from the database.
7. The attacker might be able to modify or delete data within the database.
8. The attacker achieves full database compromise, potentially leading to complete system takeover.

## Impact

Successful exploitation of CVE-2026-8129 allows an attacker to execute arbitrary SQL commands, potentially leading to the complete compromise of the application database. This could result in sensitive customer data being exposed, modified, or deleted. Attackers could also gain unauthorized access to administrative credentials, leading to full control of the online shopping platform. The vulnerability has a CVSS v3.1 score of 7.3, indicating a high severity risk.

## Recommendation

*   Inspect web server access logs for suspicious requests to `wishlist.php` with potentially malicious SQL syntax in the `delwlistid` parameter; deploy the Sigma rule `Detect SQL Injection Attempt in wishlist.php delwlistid Parameter` to identify such attempts.
*   Upgrade to a patched version of SourceCodester SUP Online Shopping that addresses CVE-2026-8129, if available from the vendor.
*   Implement input validation and sanitization on the `delwlistid` parameter in `wishlist.php` to prevent SQL injection attacks.
*   Deploy a web application firewall (WAF) rule to block requests containing known SQL injection payloads targeting `wishlist.php`.
