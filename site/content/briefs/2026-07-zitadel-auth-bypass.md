---
title: Zitadel User API Verification Code Disclosure Vulnerability
slug: 2026-07-zitadel-auth-bypass
description: An improper permission check in Zitadel's user API allows authenticated users to retrieve verification codes for arbitrary contact information, facilitating unauthorized verification of email addresses and phone numbers.
date: "2026-07-29T16:55:24Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:zitadel:zitadel:*:*:*:*:*:*:*:*
tags:
  - identity-management
  - auth-bypass
  - api-security
vendors:
  - Zitadel
products:
  - Zitadel 4.x
  - Zitadel 3.x
  - Zitadel 2.x
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Due to an improper permission check, the API allowed returning the verification code for the email and phone to the own user.
    confidence_band: high
cves:
  - id: CVE-2026-27946
    cvss: 6.5
    epss: 0.00176
references:
  - https://github.com/advisories/GHSA-jq8w-8q2f-ffm9
  - https://github.com/zitadel/zitadel/security/advisories/GHSA-282g-fhmx-xf54
---

Zitadel (CVE-2026-54693) contains a vulnerability within its User API that permits authenticated users to access verification codes for email addresses and phone numbers that do not belong to them. While a previous security advisory (CVE-2026-27946) addressed unauthorized setting of the `is_verified` flag, this secondary flaw allows users to retrieve the actual codes used for the verification workflow. By obtaining these codes, an attacker can bypass standard verification protocols for accounts or contact information they do not legitimately control. This vulnerability poses a significant risk to identity-based security policies that rely on verified email or phone ownership. The issue affects Zitadel versions 4.x (up to 4.15.0), 3.x (up to 3.4.10), and 2.x (2.43.0 through 2.71.19). Defenders should prioritize upgrading to the patched releases (4.15.1 or 3.4.11) to restore proper authorization controls.

## Impact

The vulnerability allows unauthorized users to claim ownership of contact information, potentially bypassing security policies that mandate verified contact methods for account recovery, MFA, or communication. If exploited, an attacker could assume control of identity verification workflows, leading to unauthorized account access or the masking of identity in security logs. The scope is limited to Zitadel instances configured to allow user self-management of profile data.

## Recommendation

- Upgrade Zitadel installations to versions >= 4.15.1 or >= 3.4.11 immediately to enforce correct permission checks for verification code retrieval.
- Audit existing user accounts for suspicious contact information updates or unauthorized verification states if the instance was exposed to the public.
- Implement monitoring for excessive API calls to user-management endpoints (e.g., `UpdateHumanUser` or associated verification code endpoints) from non-administrative accounts.
