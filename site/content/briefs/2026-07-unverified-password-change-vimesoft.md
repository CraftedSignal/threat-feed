---
title: 'CVE-2026-12692: Unverified Password Change Vulnerability in Vimesoft Enterprise Video Platform'
slug: 2026-07-unverified-password-change-vimesoft
description: An unverified password change vulnerability (CVE-2026-12692) exists in Vimesoft Inc.'s Enterprise Video Platform, affecting versions from 3.11.0.0 up to, but not including, 3.25.0, which allows an attacker to bypass authentication mechanisms, potentially leading to unauthorized access to the platform by changing user passwords without proper verification.
date: "2026-07-17T17:18:34Z"
lastmod: "2026-07-17T17:20:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - authentication-bypass
  - web-application
  - cve
  - critical-vulnerability
vendors:
  - Vimesoft Inc.
products:
  - Enterprise Video Platform (3.11.0.0 before 3.25.0)
  - Enterprise Video Platform (from 3.11.0.0 before 3.25.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An unverified password change vulnerability (CVE-2026-12692) exists... This flaw allows an attacker to bypass authentication mechanisms, potentially leading to unauthorized access to the platform by changing user passwords without proper verification.
    confidence_band: high
cves:
  - id: CVE-2026-12692
    cvss: 9.8
  - id: CVE-2026-12694
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12692
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0574
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12694
iocs:
  - type: url
    value: https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0574
ioc_counts:
  url: 1
updates:
  - at: "2026-07-17T17:20:18Z"
    level: L2
    summary: added CVE-2026-12694
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-12694
---

A critical authentication bypass vulnerability, identified as CVE-2026-12692, has been discovered in Vimesoft Inc.'s Enterprise Video Platform. This flaw, present in versions ranging from 3.11.0.0 through to 3.24.9 (before 3.25.0), allows an unauthenticated attacker to change user passwords without prior verification. The vulnerability stems from an "Unverified Password Change" (CWE-620) mechanism, enabling malicious actors to reset or set new passwords for existing user accounts without requiring the current password or a secure token. Successful exploitation grants attackers complete unauthorized access to affected user accounts and the entire video platform, posing a severe risk to data integrity, confidentiality, and system availability. This vulnerability carries a CVSS v3.1 base score of 9.8, indicating its critical severity and ease of exploitation.

## Attack Chain

1. Attacker identifies a vulnerable Vimesoft Inc. Enterprise Video Platform instance running a version between 3.11.0.0 and 3.24.9.
2. The attacker targets a valid user account on the platform, whose username or email address is known or can be enumerated.
3. The attacker crafts and sends a specific HTTP request to the platform's password reset or password change endpoint for the target user.
4. Due to the "Unverified Password Change" vulnerability (CVE-2026-12692), the platform processes this request and updates the target user's password without validating the user's identity or requiring the old password/a secure reset token.
5. The platform responds, indicating the password change was successful, or provides an error message that can be used for further enumeration.
6. The attacker then uses the target user's username and the newly set password to log into the Vimesoft Enterprise Video Platform.
7. The attacker gains full unauthorized access to the compromised user's account and all associated platform functionalities and data.

## Impact

Successful exploitation of CVE-2026-12692 results in complete compromise of user accounts within the Vimesoft Enterprise Video Platform. Attackers can gain unauthorized access to sensitive video content, user data, and administrative functions, depending on the privileges of the compromised account. This can lead to data exfiltration, modification, or deletion of critical information, disruption of video services, and potential defacement of the platform. The broad range of affected versions indicates a significant potential victim base. For organizations using the vulnerable platform, the impact could include severe reputational damage, regulatory penalties for data breaches, and operational disruption.

## Recommendation

* Patch CVE-2026-12692 immediately by updating Vimesoft Enterprise Video Platform to version 3.25.0 or later to remediate the unverified password change vulnerability.
* Monitor web server access logs for repeated or unusual password change requests, especially those originating from unexpected IP addresses or associated with administrative accounts.
* Implement multi-factor authentication (MFA) for all user accounts, particularly those with elevated privileges, to add an additional layer of security against compromised credentials.
* Conduct regular security audits and penetration tests on Vimesoft Enterprise Video Platform instances to identify and address similar authentication bypass vulnerabilities.
