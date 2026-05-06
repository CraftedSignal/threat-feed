---
title: Gravity Bookings Premium Plugin SQL Injection Vulnerability
slug: 2026-05-gravity-bookings-sqli
description: The Gravity Bookings Premium plugin for WordPress is vulnerable to SQL Injection in versions up to 2.5.9, allowing unauthenticated attackers to extract sensitive information from the database.
date: "2026-05-06T10:16:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - wordpress
  - plugin
vendors:
  - Gravity Booking
products:
  - Gravity Bookings Premium plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-1719
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1719
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/ce032abe-ee9d-4be1-ac97-5fa95d598e85?source=cve
rules:
  - title: Detect WordPress Gravity Bookings SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the Gravity Bookings Premium plugin based on suspicious URI patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Gravity Bookings SQL Injection via POST data
    description: Detects potential SQL injection attempts targeting the Gravity Bookings Premium plugin based on suspicious POST data patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Gravity Bookings Premium plugin for WordPress is susceptible to SQL Injection, as reported in CVE-2026-1719. The vulnerability affects all versions up to and including 2.5.9. It stems from insufficient input sanitization on user-supplied parameters combined with inadequate preparation of existing SQL queries. An unauthenticated attacker can exploit this by injecting malicious SQL queries into legitimate ones, potentially gaining unauthorized access to sensitive data within the WordPress database. This can lead to data breaches, privilege escalation, and other severe security incidents. The vulnerability was reported by Wordfence.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable endpoint in the Gravity Bookings Premium plugin that accepts user input.
2. The attacker crafts a malicious SQL query, embedding it within a legitimate-looking request to the vulnerable endpoint.
3. The crafted query exploits the lack of proper input sanitization to bypass security measures.
4. The injected SQL code is appended to the existing SQL query executed by the WordPress application.
5. The modified SQL query is executed against the WordPress database.
6. The injected SQL query extracts sensitive information, such as user credentials, booking details, or other confidential data.
7. The extracted data is returned to the attacker as part of the application's response or through other channels, such as database logs.

## Impact

Successful exploitation of this SQL Injection vulnerability (CVE-2026-1719) can lead to the exposure of sensitive data stored in the WordPress database. This may include user credentials, personal information, and booking details. An attacker could use this information to compromise user accounts, gain unauthorized access to the WordPress administration panel, or launch further attacks against the system. The number of affected websites is potentially significant, given the popularity of the Gravity Bookings Premium plugin.

## Recommendation

*   Upgrade the Gravity Bookings Premium plugin to the latest version (greater than 2.5.9) to patch CVE-2026-1719.
*   Deploy the Sigma rule "Detect WordPress Gravity Bookings SQL Injection Attempt" to identify potential exploitation attempts in web server logs.
*   Monitor web server logs for suspicious HTTP requests targeting the Gravity Bookings Premium plugin with potentially malicious SQL queries.
