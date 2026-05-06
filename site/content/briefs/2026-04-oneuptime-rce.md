---
title: OneUptime Unauthenticated Endpoint Access Vulnerability (CVE-2026-34758)
slug: 2026-04-oneuptime-rce
description: OneUptime versions prior to 10.0.42 are vulnerable to unauthenticated access to Notification test and Phone Number management endpoints, leading to potential abuse of SMS, Call, Email, and WhatsApp functionalities, and unauthorized phone number purchases, fixed in version 10.0.42.
date: "2026-04-02T19:21:33Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve
  - vulnerability
  - oneuptime
  - unauthenticated-access
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34758
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34758
  - https://github.com/OneUptime/oneuptime/commit/9adbd04538714740506708d6fa610e433be4d2a4
  - https://github.com/OneUptime/oneuptime/releases/tag/10.0.42
  - https://github.com/OneUptime/oneuptime/security/advisories/GHSA-q253-6wcm-h8hp
rules:
  - title: Detect Unauthenticated OneUptime Notification Test Access
    description: Detects unauthenticated access attempts to the OneUptime notification test endpoint, indicative of CVE-2026-34758 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthenticated OneUptime Phone Number Purchase Access
    description: Detects unauthenticated access attempts to the OneUptime phone number purchase endpoint, indicative of CVE-2026-34758 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OneUptime, an open-source monitoring and observability platform, is susceptible to a critical vulnerability (CVE-2026-34758) affecting versions prior to 10.0.42. This vulnerability stems from the lack of authentication on critical Notification test and Phone Number management endpoints. Exploitation of this flaw could enable attackers to abuse SMS, call, email, and WhatsApp functionalities, potentially sending unsolicited messages or incurring costs for the affected organization. Furthermore, the vulnerability permits unauthorized phone number purchases, leading to financial and reputational damage. The vulnerability was reported on April 2, 2026, and patched in version 10.0.42. Organizations using affected versions of OneUptime should upgrade immediately.

## Attack Chain

1.  The attacker identifies a vulnerable OneUptime instance running a version prior to 10.0.42.
2.  The attacker crafts a malicious HTTP request targeting the unauthenticated Notification test endpoint (e.g., `/api/notification/test`).
3.  The attacker injects arbitrary parameters into the request to control the SMS, Call, Email, or WhatsApp message content and recipients.
4.  The OneUptime server processes the request without authentication, triggering the sending of attacker-controlled messages.
5.  The attacker crafts a malicious HTTP request targeting the unauthenticated Phone Number management endpoint (e.g., `/api/phone-number/purchase`).
6.  The attacker provides details for a phone number purchase.
7.  The OneUptime server processes the request without authentication, initiating a phone number purchase, potentially incurring financial charges.
8.  The attacker leverages the purchased phone number for malicious activities, such as phishing or social engineering attacks.

## Impact

Successful exploitation of CVE-2026-34758 can lead to significant repercussions. Attackers can abuse messaging services, sending spam, phishing links, or malicious content via SMS, email, and WhatsApp, impacting potentially thousands of users. Furthermore, unauthorized phone number purchases can result in unexpected financial costs and create opportunities for attackers to conduct further malicious activities, damaging the organization's reputation and potentially leading to legal liabilities. The vulnerable versions of OneUptime expose organizations to significant risk until upgraded to version 10.0.42 or later.

## Recommendation

*   Immediately upgrade OneUptime installations to version 10.0.42 or later to patch CVE-2026-34758.
*   Monitor web server logs for suspicious requests to the `/api/notification/test` and `/api/phone-number/purchase` endpoints, as described in the Attack Chain.
*   Deploy the Sigma rule "Detect Unauthenticated OneUptime Notification Test Access" to identify potential exploitation attempts in real-time.
*   Deploy the Sigma rule "Detect Unauthenticated OneUptime Phone Number Purchase Access" to identify potential exploitation attempts in real-time.
