---
title: CVE-2026-2347 - Akilli Commerce E-Commerce Website Authorization Bypass via User-Controlled Key
slug: 2026-05-akilli-auth-bypass
description: CVE-2026-2347 describes an authorization bypass vulnerability through a user-controlled key in Akilli Commerce Software Technologies Ltd. Co. E-Commerce Website before version 4.5.001, which could lead to session hijacking.
date: "2026-05-14T10:17:24Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - cve
  - cve-2026-2347
  - authorization bypass
  - session hijacking
  - ecommerce
vendors:
  - Akilli Commerce Software Technologies Ltd. Co.
products:
  - E-Commerce Website
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-2347
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-2347
rules:
  - title: Detect CVE-2026-2347 Exploitation Attempt via Modified Session Key
    description: Detects CVE-2026-2347 exploitation — An attacker attempts to modify a user-controlled key to bypass authorization and hijack sessions on Akilli Commerce E-Commerce Website.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1550
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-2347 details an authorization bypass vulnerability affecting Akilli Commerce Software Technologies Ltd. Co.'s E-Commerce Website. The vulnerability, present in versions prior to 4.5.001, stems from a user-controlled key issue that enables session hijacking. An attacker could potentially exploit this vulnerability to gain unauthorized access to user accounts and sensitive data within the e-commerce platform. This is a critical vulnerability because it directly impacts the confidentiality and integrity of user sessions, potentially leading to financial loss, data breaches, and reputational damage for the affected e-commerce website.

## Attack Chain

1.  Attacker identifies an Akilli Commerce E-Commerce Website running a vulnerable version (<= 4.5.001).
2.  Attacker crafts a malicious request to the website, manipulating the user-controlled key parameter.
3.  The manipulated key bypasses authorization checks on the e-commerce platform.
4.  The attacker obtains a valid session identifier, effectively hijacking an existing user session.
5.  Attacker authenticates to the web application using the hijacked session ID.
6.  Attacker accesses sensitive information related to the compromised user account, such as personal details, order history, or payment information.
7.  The attacker performs actions on behalf of the victim, potentially making unauthorized purchases or modifying account settings.

## Impact

Successful exploitation of CVE-2026-2347 allows an attacker to bypass authentication mechanisms and hijack user sessions. This could lead to the compromise of user accounts, theft of sensitive data, unauthorized transactions, and reputational damage for the affected e-commerce website. The impact is potentially widespread, affecting any user of a vulnerable Akilli Commerce E-Commerce Website.

## Recommendation

*   Upgrade Akilli Commerce E-Commerce Website to version 4.5.001 or later to patch CVE-2026-2347.
*   Deploy the Sigma rule "Detect CVE-2026-2347 Exploitation Attempt via Modified Session Key" to monitor for attempts to exploit this vulnerability.
