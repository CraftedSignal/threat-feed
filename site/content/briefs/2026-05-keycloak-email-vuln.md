---
title: Keycloak Vulnerability Allows Arbitrary Email Sending
slug: 2026-05-keycloak-email-vuln
description: An anonymous, remote attacker can exploit a vulnerability in Keycloak to send arbitrary emails, potentially leading to phishing or social engineering attacks.
date: "2026-05-13T07:59:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - keycloak
  - email
  - vulnerability
  - spoofing
vendors:
  - Keycloak
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-1870
rules:
  - title: Detect Suspicious Keycloak Email Activity
    description: Detects suspicious activity related to Keycloak's email sending functionality, potentially indicating exploitation of the vulnerability allowing arbitrary email sending.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
  - title: Detect Keycloak Unauthenticated Email Sending
    description: Detects potential attempts to send emails via Keycloak without proper authentication, potentially exploiting a vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability exists within Keycloak that allows an unauthenticated, remote attacker to send arbitrary emails. The BSI advisory (WID-SEC-2025-1870) highlights the potential for exploitation. This vulnerability is significant because it enables attackers to leverage Keycloak's email functionality for malicious purposes, such as sending phishing emails, distributing malware, or conducting social engineering attacks against users of systems integrated with Keycloak. Successful exploitation could damage trust in the platform and compromise user accounts.

## Attack Chain

1.  Attacker identifies a Keycloak instance exposed to the internet.
2.  Attacker crafts a malicious request exploiting the email sending vulnerability.
3.  The malicious request bypasses authentication and authorization checks related to email functionality.
4.  Keycloak processes the attacker's request without proper validation.
5.  Keycloak's email service sends an email with attacker-controlled content.
6.  The email is delivered to the targeted recipient(s).
7.  The recipient interacts with the malicious email (e.g., clicks a link, opens an attachment).
8.  The attacker achieves their objective (e.g., credential harvesting, malware infection).

## Impact

Successful exploitation of this vulnerability could lead to the distribution of phishing emails, malware, or other malicious content, potentially compromising user accounts or systems integrated with Keycloak. The impact includes potential reputational damage, data breaches, and financial losses. While the number of affected systems is not specified in the advisory, all Keycloak instances are potentially vulnerable if not patched.

## Recommendation

*   Upgrade Keycloak to the latest patched version to remediate the email sending vulnerability.
*   Monitor Keycloak logs for suspicious email activity, as detected by the Sigma rule "Detect Suspicious Keycloak Email Activity".
*   Implement rate limiting on email sending functionality within Keycloak to mitigate abuse, and monitor for bypass attempts.
