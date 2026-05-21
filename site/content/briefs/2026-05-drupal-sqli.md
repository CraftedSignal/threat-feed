---
title: Drupal Core PostgreSQL SQL Injection Vulnerability (CVE-2026-9082) Exploit Available
slug: 2026-05-drupal-sqli
description: A public exploit is available for CVE-2026-9082, a SQL injection vulnerability in Drupal Core affecting PostgreSQL-backed sites running versions 8.0 through 11.3.9, allowing unauthenticated users to potentially achieve data exfiltration, privilege escalation, and remote code execution.
date: "2026-05-21T11:02:28Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - cve
  - sql injection
  - drupal
  - web application
vendors:
  - Drupal
products:
  - Drupal Core (8.0.0 - 11.3.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9082
    cvss: 6.5
references:
  - https://sploitus.com/exploit?id=89259320-7066-518A-B075-CE8CD77E926F&utm_source=rss&utm_medium=rss
  - SA-CORE-2026-004
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=89259320-7066-518A-B075-CE8CD77E926F&utm_source=rss&utm_medium=rss
  - type: url
    value: https://github.com/7h30th3r0n3/CVE-2026-9082-Drupal-PoC.git
ioc_counts:
  url: 2
rules:
  - title: Detect CVE-2026-9082 Exploitation Attempt — Drupal SQL Injection via JSON:API
    description: Detects CVE-2026-9082 exploitation attempt — HTTP request to the Drupal JSON:API endpoint with SQL injection patterns in the filter parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9082 Exploitation Attempt — Drupal SQL Injection via JSON:API (Boolean Based)
    description: Detects CVE-2026-9082 exploitation attempt — HTTP request to the Drupal JSON:API endpoint with boolean based SQL injection patterns in the filter parameters.
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

A proof-of-concept exploit has been published for CVE-2026-9082, a critical SQL injection vulnerability affecting Drupal Core when using a PostgreSQL database backend. The vulnerability impacts Drupal versions 8.0.0 through 11.3.9. The vulnerability resides in the PostgreSQL Entity Query Condition handler. The issue can be exploited by unauthenticated users through the JSON:API module, which is enabled by default since Drupal 9. Successful exploitation could lead to unauthorized data access, privilege escalation, and potentially remote code execution in certain server configurations. The existence of a public exploit increases the risk to unpatched Drupal installations.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP request to a vulnerable Drupal server using the JSON:API endpoint.
2. The request includes malicious SQL code embedded within the array keys of the filter conditions in the URL parameters.
3. Drupal's PostgreSQL Entity Query Condition handler processes the request and iterates over the provided array keys.
4. The `translateCondition()` method constructs PDO placeholder names using the attacker-controlled array keys.
5. Due to insufficient sanitization, the malicious SQL code is injected into the PDO placeholder name.
6. The injected SQL code bypasses the intended query sanitization mechanisms.
7. The database executes the injected SQL code, allowing the attacker to manipulate database queries.
8. The attacker can extract sensitive data, escalate privileges, or potentially execute arbitrary code on the server (RCE) in certain configurations.

## Impact

Successful exploitation of CVE-2026-9082 can lead to significant consequences for affected Drupal websites. Attackers can exfiltrate sensitive data from the database, including user credentials, personally identifiable information (PII), and other confidential data. Privilege escalation allows attackers to gain administrative access to the Drupal site, enabling them to modify content, install malicious modules, or compromise the entire server. In some server configurations, the vulnerability can be leveraged to achieve remote code execution (RCE), granting the attacker complete control over the system. Given the broad usage of Drupal, a successful widespread attack could impact numerous organizations across various sectors.

## Recommendation

*   Apply the patches provided in Drupal SA-CORE-2026-004 to address CVE-2026-9082. Upgrade to Drupal Core versions 11.3.10, 11.2.12, 10.6.9, or 10.5.10 depending on your current branch to remediate the vulnerability.
*   Monitor web server logs for suspicious HTTP requests targeting the JSON:API endpoint (`/jsonapi`) with unusual filter parameters containing SQL metacharacters, as described in the Attack Chain (webserver category).
*   Deploy the Sigma rule "Detect CVE-2026-9082 Exploitation Attempt — Drupal SQL Injection via JSON:API" to detect potential exploitation attempts in real-time.
*   Block access to the identified malicious Git repository URL (`https://github.com/7h30th3r0n3/CVE-2026-9082-Drupal-PoC.git`) to prevent internal systems from downloading the exploit code (IOC).
