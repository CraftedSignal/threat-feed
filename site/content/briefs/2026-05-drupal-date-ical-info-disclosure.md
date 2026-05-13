---
title: Drupal Date iCal Module Vulnerability Allows Information Disclosure
slug: 2026-05-drupal-date-ical-info-disclosure
description: A critical information disclosure vulnerability exists in the Drupal Date iCal module versions prior to 4.0.15, potentially allowing unauthorized access to sensitive information.
date: "2026-05-13T18:36:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - drupal
  - information-disclosure
  - vulnerability
vendors:
  - Drupal
products:
  - Date iCal < 4.0.15
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
references:
  - https://cyber.gc.ca/en/alerts-advisories/drupal-security-advisory-av26-463
  - https://www.drupal.org/sa-contrib-2026-037
  - https://www.drupal.org/security
rules:
  - title: Detect Drupal Date iCal Information Disclosure Attempt
    description: Detects potential attempts to exploit the Drupal Date iCal information disclosure vulnerability by monitoring for suspicious URI patterns.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1592.002
    data_sources:
      - webserver
  - title: Detect Drupal Date iCal Access to Sensitive Files
    description: Detects potential information disclosure by monitoring access attempts to sensitive files within the Date iCal module directory.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1592.002
    data_sources:
      - webserver
rules_count: 2
---

On May 13, 2026, Drupal released a security advisory addressing multiple vulnerabilities, including a critical information disclosure issue in the Date iCal module. This module, if used in versions prior to 4.0.15, is susceptible to unauthorized information exposure. The vulnerability, tracked as SA-CONTRIB-2026-037, could allow attackers to gain access to sensitive data that should otherwise be protected. Organizations using affected versions of Date iCal are urged to upgrade immediately to mitigate the risk. This vulnerability impacts any Drupal sites using the Date iCal module prior to version 4.0.15.

## Attack Chain

1. An attacker identifies a Drupal website using a vulnerable version of the Date iCal module (prior to 4.0.15).
2. The attacker crafts a specific HTTP request targeting the Date iCal module.
3. The malicious request exploits the information disclosure vulnerability.
4. The vulnerable module improperly processes the request, leading to unintended data exposure.
5. The attacker gains access to sensitive information that should have been protected.
6. The attacker may use the disclosed information to further compromise the Drupal website or its users.

## Impact

Successful exploitation of this vulnerability could lead to the disclosure of sensitive information, potentially impacting user privacy and confidentiality. The exact scope of the information disclosed depends on the specific implementation of the Date iCal module and the data it handles. However, due to the 'critical' severity rating, the potential impact is considered significant, warranting immediate attention and patching.

## Recommendation

*   Upgrade the Date iCal module to version 4.0.15 or later to remediate the information disclosure vulnerability as advised in [SA-CONTRIB-2026-037](https://www.drupal.org/sa-contrib-2026-037).
*   Monitor web server logs for unusual requests targeting the Date iCal module to detect potential exploitation attempts. Use the rule "Detect Drupal Date iCal Information Disclosure Attempt" below.
*   Review and audit the data handled by the Date iCal module to assess the potential impact of information disclosure.
