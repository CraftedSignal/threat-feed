---
title: Critical SQL Injection Vulnerability in Drupal Location Selector Module (SA-CONTRIB-2026-072)
slug: 2026-07-drupal-sqli
description: A critical SQL Injection vulnerability (SA-CONTRIB-2026-072) has been identified in Drupal's Location Selector module, affecting versions prior to 1.3.0, allowing unauthenticated attackers to execute arbitrary SQL commands and potentially leading to unauthorized data access, modification, or deletion.
date: "2026-07-08T19:04:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - web-application
  - drupal
vendors:
  - Drupal
products:
  - Location Selector module < 1.3.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'Included was a critical update for the following: Location Selector – versions prior to 1.3.0...SQL Injection – SA-CONTRIB-2026-072'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This vulnerability allows an unauthenticated attacker to execute arbitrary SQL commands against the backend database, potentially leading to unauthorized data access.
    confidence_band: med
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: The stolen data is then exfiltrated by the attacker, often embedded within the legitimate HTTP responses.
    confidence_band: med
references:
  - https://cyber.gc.ca/en/alerts-advisories/drupal-security-advisory-av26-676
  - https://www.drupal.org/sa-contrib-2026-072
  - https://www.drupal.org/security
rules:
  - title: Detect SA-CONTRIB-2026-072 Exploitation - Drupal Location Selector SQLi
    description: Detects exploitation attempts for SA-CONTRIB-2026-072, a critical SQL Injection vulnerability in Drupal's Location Selector module, by identifying common SQLi payloads in web request query strings or URL paths.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

On July 8, 2026, the Canadian Centre for Cyber Security (CCCS) published an advisory (AV26-676) warning of a critical SQL Injection vulnerability (SA-CONTRIB-2026-072) affecting Drupal's Location Selector module, specifically versions prior to 1.3.0. This vulnerability allows an unauthenticated attacker to execute arbitrary SQL commands against the backend database, potentially leading to unauthorized data access, modification, or deletion. The critical nature of this flaw necessitates immediate attention from defenders, as successful exploitation could compromise the integrity and confidentiality of data stored on affected Drupal sites. Organizations utilizing the Location Selector module are strongly advised to apply the security updates promptly to prevent potential exploitation. This advisory highlights the ongoing risk posed by web application vulnerabilities and the importance of timely patching.

## Attack Chain

1. Attacker identifies an internet-facing Drupal instance running the vulnerable Location Selector module (versions prior to 1.3.0).
2. Attacker crafts a specially malformed HTTP request, embedding an SQL injection payload within a vulnerable parameter exposed by the module.
3. The Drupal web server processes the malicious request, passing the untrusted input to the application's backend database query.
4. The embedded SQL payload is executed by the database, allowing the attacker to bypass authentication, query arbitrary tables, or manipulate database content.
5. The attacker uses this access to extract sensitive information, such as user credentials, session tokens, or proprietary organizational data.
6. The stolen data is then exfiltrated by the attacker, often embedded within the legitimate HTTP responses or through direct database connections established via the injection.

## Impact

Successful exploitation of this critical SQL Injection vulnerability in the Drupal Location Selector module could lead to severe consequences for affected organizations. Attackers could gain unauthorized access to an organization's entire database, including sensitive customer data, proprietary business information, or user credentials. This compromise can result in significant data breaches, reputational damage, financial losses due to regulatory penalties, and potential operational disruption. Depending on the database configuration, SQL injection could also lead to remote code execution (RCE) on the underlying server, further escalating the impact to full system compromise. While no specific victim count or targeted sectors were mentioned, any organization using the vulnerable module is at risk.

## Recommendation

* Apply the update for Drupal Location Selector module to version 1.3.0 or later immediately, as advised in the CCCS advisory AV26-676 and Drupal SA-CONTRIB-2026-072.
* Deploy the Sigma rule in this brief to your SIEM to detect potential SQL Injection attempts against your web applications.
* Review web server access logs for anomalous requests containing common SQL injection patterns, especially targeting any Drupal Location Selector module endpoints.
* Enable robust logging for web servers, including full request URLs, query strings, and POST data, to assist in detecting and investigating web-based attacks.
