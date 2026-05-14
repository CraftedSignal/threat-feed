---
title: Fluent Forms WordPress Plugin IDOR Vulnerability (CVE-2026-5395)
slug: 2026-05-fluentforms-idor
description: The Fluent Forms WordPress plugin through 6.2.0 is vulnerable to Insecure Direct Object Reference (IDOR), allowing authenticated users with manager-level access or higher to bypass form-level access controls, export arbitrary database tables, and enumerate table names via error messages, as tracked by CVE-2026-5395.
date: "2026-05-14T07:18:04Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - insecure-direct-object-reference
  - wordpress
  - fluentforms
  - cve-2026-5395
vendors:
  - WordPress
products:
  - Fluent Forms – Customizable Contact Forms, Survey, Quiz, & Conversational Form Builder plugin <= 6.2.0
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1068
    technique_name: Exploitation for Credential Access
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Credential Access
cves:
  - id: CVE-2026-5395
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5395
rules:
  - title: Detect CVE-2026-5395 Exploitation Attempt via Fluent Forms IDOR
    description: Detects CVE-2026-5395 exploitation attempt — HTTP request to the Fluent Forms exportEntries function with suspicious parameters indicative of IDOR.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Fluent Forms Database Table Enumeration via Error Messages
    description: Detects Fluent Forms database table enumeration via error messages containing database table names.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - webserver
rules_count: 2
---

The Fluent Forms – Customizable Contact Forms, Survey, Quiz, & Conversational Form Builder plugin for WordPress, versions up to and including 6.2.0, contains an Insecure Direct Object Reference (IDOR) vulnerability. This flaw resides within the `exportEntries` function. The vulnerability stems from a lack of proper validation on a user-controlled key, enabling authenticated attackers with manager-level access or higher to circumvent form-level access restrictions. This allows them to access submissions from forms they lack authorization to view. The issue was reported on May 14, 2026, and is tracked as CVE-2026-5395. Exploitation can lead to unauthorized data access, potential data exfiltration, and information disclosure.

## Attack Chain

1. An attacker authenticates to the WordPress instance with manager-level or higher privileges.
2. The attacker crafts a malicious HTTP request targeting the `exportEntries` function.
3. The request includes a manipulated user-controlled key to bypass form-level access restrictions.
4. Due to the missing validation, the application processes the request without verifying the attacker's authorization to the target form.
5. The attacker gains unauthorized access to form submissions from forms they are not authorized to view.
6. The attacker exploits the same IDOR vulnerability to export data from arbitrary database tables by manipulating the key.
7. The attacker leverages error messages disclosed by the application to enumerate database table names.
8. The attacker exfiltrates the sensitive data obtained from unauthorized access to form submissions and exported database tables.

## Impact

Successful exploitation of CVE-2026-5395 allows attackers to bypass access controls and gain unauthorized access to sensitive form submission data. This can lead to the exposure of personal information, business intelligence, or other confidential data collected through the forms. The ability to export arbitrary database tables further expands the scope of the attack, potentially compromising the entire WordPress database. The enumeration of database table names provides attackers with valuable information for further reconnaissance and exploitation attempts.

## Recommendation

*   Apply the latest security updates for the Fluent Forms plugin to patch CVE-2026-5395.
*   Deploy the Sigma rule "Detect CVE-2026-5395 Exploitation Attempt via Fluent Forms IDOR" to monitor for suspicious requests to the `exportEntries` function in the webserver logs.
*   Review user access controls and ensure that users have only the necessary privileges to access specific forms to mitigate potential internal threats.
*   Enable detailed logging for the WordPress application to capture relevant events for investigating potential exploitation attempts.
