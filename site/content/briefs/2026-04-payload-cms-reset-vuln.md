---
title: Payload CMS Password Reset Vulnerability (CVE-2026-34751)
slug: 2026-04-payload-cms-reset-vuln
description: An unauthenticated attacker can perform actions on behalf of a user initiating a password reset in Payload CMS versions prior to 3.79.1 due to a flaw in the password recovery flow, potentially leading to account takeover or privilege escalation.
date: "2026-04-01T18:16:31Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-34751
  - payload-cms
  - password-reset
  - vulnerability
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1199
    technique_name: Bypass Password Reset
cves:
  - id: CVE-2026-34751
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34751
  - https://github.com/payloadcms/payload/releases/tag/v3.79.1
  - https://github.com/payloadcms/payload/security/advisories/GHSA-hp5w-3hxx-vmwf
rules:
  - title: Detect Payload CMS Password Reset Abuse
    description: Detects potential abuse of the Payload CMS password reset functionality by monitoring for unusual patterns of password reset requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1078.004
    data_sources:
      - webserver
      - linux
  - title: Detect Payload CMS Password Change Attempt from Unusual Source
    description: Detects password change attempts from IP addresses that have not previously authenticated.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1078.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Payload CMS is a free and open-source headless content management system. Prior to version 3.79.1, a critical vulnerability (CVE-2026-34751) exists in the `@payloadcms/graphql` and `payload` components concerning the password recovery flow. This flaw allows an unauthenticated attacker to potentially perform actions as a legitimate user who has initiated a password reset process. The vulnerability arises from improper handling of password reset tokens or insufficient validation during the password reset process. The maintainers addressed this issue in version 3.79.1. Organizations using affected versions of Payload CMS should upgrade immediately to prevent potential account compromise.

## Attack Chain

1.  Attacker identifies a valid username on the Payload CMS instance.
2.  Attacker initiates the password reset process for the target user via the CMS login page.
3.  The CMS sends a password reset email to the valid user, containing a unique password reset link.
4.  The attacker intercepts or gains access to the password reset link (e.g., via sniffing network traffic, although unlikely in a modern HTTPS-enabled setup, or social engineering).
5.  Attacker uses the intercepted password reset link to access the password reset form.
6.  Due to the vulnerability, the attacker can successfully change the password without proper validation or authorization checks beyond the initial link.
7.  The attacker sets a new password for the user account.
8.  The attacker logs into the Payload CMS using the compromised account credentials, gaining unauthorized access and potentially escalating privileges depending on the account's role.

## Impact

Successful exploitation of CVE-2026-34751 allows an unauthenticated attacker to compromise user accounts within the Payload CMS. The impact ranges from unauthorized data access and modification to complete account takeover, potentially affecting all users on the CMS instance, including administrators. Given the headless nature of Payload CMS, this can lead to content manipulation, defacement, or even backend data breaches, impacting any applications or services relying on the CMS for content delivery.

## Recommendation

*   Upgrade Payload CMS to version 3.79.1 or later to patch CVE-2026-34751, addressing the flawed password recovery flow.
*   Implement the Sigma rule `Detect Payload CMS Password Reset Abuse` to detect suspicious password reset activity (log source: webserver).
*   Monitor web server logs for unusual password reset requests or access patterns, and correlate these with potential attempts to exploit CVE-2026-34751.
*   Consider implementing multi-factor authentication (MFA) to mitigate the risk of account takeover even if the password reset process is compromised.
*   Review and strengthen password policies, encouraging users to use strong, unique passwords to minimize the impact of credential compromise.
*   Monitor for password reset requests originating from unusual source IPs (log source: webserver).
