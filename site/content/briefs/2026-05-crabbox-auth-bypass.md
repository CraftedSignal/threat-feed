---
title: Crabbox Coordinator Authentication Bypass Vulnerability (CVE-2026-45223)
slug: 2026-05-crabbox-auth-bypass
description: 'Crabbox before 0.9.0 is vulnerable to an authentication bypass (CVE-2026-45223) in the coordinator user-token verification, allowing attackers with a non-admin token to escalate privileges to full coordinator admin access by crafting a malicious user-token with an ''admin: true'' claim.'
date: "2026-05-11T19:17:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - privilege-escalation
  - cve
vendors:
  - Crabbox
products:
  - Crabbox
  - Crabbox Coordinator (< 0.9.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-45223
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45223
  - CVE-2026-45223
rules:
  - title: Detect Crabbox Coordinator Admin Claim Forgery
    description: Detects CVE-2026-45223 exploitation — monitors for abnormal user-token payloads containing an admin claim being presented to Crabbox Coordinator admin routes.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
  - title: Detect Crabbox Coordinator Forced Release Operations
    description: Detects suspicious activity related to forced release operations performed by unauthorized users on the Crabbox Coordinator.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 2
---

Crabbox, a data management system, contains an authentication bypass vulnerability, tracked as CVE-2026-45223, affecting versions prior to 0.9.0. The vulnerability lies within the coordinator's user-token verification process. Specifically, the `verifyUserToken()` function fails to properly validate user tokens, allowing an attacker possessing a valid, but non-administrative, user token to forge an administrative token. By crafting a user-token payload containing the `admin: true` claim and signing it with HMAC-SHA256, an attacker can bypass authentication checks on admin-only coordinator routes. This grants them unauthorized access to sensitive coordinator functions, enabling them to view leases, manage pool states, and perform forced release operations. This vulnerability poses a significant risk to organizations using Crabbox, as it allows for complete takeover of the coordinator component and associated data management functions.

## Attack Chain

1.  Attacker obtains a valid, non-administrative user token for the Crabbox coordinator. This could be achieved through legitimate user registration or compromise of an existing user account.
2.  Attacker crafts a malicious user-token payload. The payload includes the `admin: true` claim, which indicates administrative privileges.
3.  Attacker signs the crafted payload using HMAC-SHA256, leveraging knowledge of the signing key (potentially obtained through other vulnerabilities or exposures).
4.  Attacker presents the crafted and signed user token to an admin-only coordinator route.
5.  The `verifyUserToken()` function fails to reject the payload due to the presence of the `admin: true` claim, bypassing the intended authentication restrictions.
6.  The coordinator grants the attacker full administrator access based on the forged token.
7.  Attacker leverages the elevated privileges to access sensitive information, such as lease visibility and pool state management.
8.  Attacker performs unauthorized actions, such as forced release operations or manipulation of pool configurations, leading to data corruption or service disruption.

## Impact

Successful exploitation of CVE-2026-45223 allows an attacker to gain complete control over the Crabbox coordinator component. This grants the attacker access to sensitive data management functions, including lease visibility, pool state management, and forced release operations. The attacker can manipulate pool configurations, potentially leading to data corruption or service disruption. Given the high CVSS score of 8.8, this vulnerability poses a significant risk to organizations using Crabbox. The number of potential victims is directly related to the number of Crabbox deployments using versions prior to 0.9.0. The sectors most affected would be those relying on Crabbox for critical data management processes.

## Recommendation

*   Upgrade Crabbox to version 0.9.0 or later to patch CVE-2026-45223.
*   Implement monitoring and alerting for suspicious activity on the Crabbox coordinator, such as unexpected changes to pool configurations or unauthorized forced release operations.
*   Deploy the Sigma rule "Detect Crabbox Coordinator Admin Claim Forgery" to detect attempts to forge admin tokens.
*   Review access controls and ensure that only authorized users have access to the Crabbox coordinator.
