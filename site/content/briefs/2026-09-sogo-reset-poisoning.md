---
title: CVE-2026-93453 Password Reset Poisoning in SOGo
slug: 2026-09-sogo-reset-poisoning
description: SOGo versions before 5.12.11 are vulnerable to password reset poisoning, allowing unauthenticated attackers to manipulate reset links by injecting malicious values into the Origin header.
date: "2026-09-18T02:01:41Z"
lastmod: "2026-09-18T09:27:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:alinto:sogo:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=8D42E2DA-4559-5F60-A8C3-DF95BE8B7FD0&utm_source=rss&utm_medium=rss
tags:
  - web-application
  - credential-theft
  - cve-2026-93453
vendors:
  - Alinto
products:
  - SOGo (< 5.12.11)
  - SOGo (<= 5.12.10)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can submit password recovery requests with a malicious Origin header to have valid password-reset tokens mailed to victim recovery addresses within links pointing to attacker infrastructure, enabling account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-93453
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93453
  - https://sploitus.com/exploit?id=8D42E2DA-4559-5F60-A8C3-DF95BE8B7FD0&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade SOGo to version 5.12.11 or later
      owner: IT Operations
      due: 24h
      evidence: SOGo before 5.12.11 constructs password-reset links using the client-supplied Origin header
  mitigation_plan:
    - priority: immediate
      action: Configure web proxy to block or sanitize 'Origin' header for password reset endpoints
      owner: IT Operations
      addresses: CVE-2026-93453
      evidence: Improper use of the client-supplied Origin header
updates:
  - at: "2026-09-18T09:27:01Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=8D42E2DA-4559-5F60-A8C3-DF95BE8B7FD0&utm_source=rss&utm_medium=rss
---

CVE-2026-93453 affects SOGo, a collaborative software suite, in versions prior to 5.12.11. The vulnerability exists due to improper input validation where the application uses the client-supplied 'Origin' HTTP header to construct the base URL for password-reset links sent via email. 

An unauthenticated attacker can exploit this by initiating a password-reset request for a target user account while simultaneously providing a crafted 'Origin' header in the HTTP request. The SOGo backend fails to sanitize this input, resulting in the generation of a legitimate reset token delivered to the user, but embedded within a URL pointing to an attacker-controlled server. If the victim clicks this link, the recovery token is leaked to the attacker's server, facilitating full account takeover. This flaw is particularly impactful for organizations relying on SOGo for email and calendar management.

## Impact

Successful exploitation allows unauthenticated attackers to hijack user accounts by capturing password-reset tokens. This vulnerability poses a severe risk to organizational security, potentially leading to unauthorized access to sensitive internal communications, calendars, and organizational data. The impact is elevated given that the attack is unauthenticated and can be automated to target multiple users.

## Recommendation

1. Upgrade SOGo to version 5.12.11 or later immediately to patch CVE-2026-93453.
2. Implement strict input validation or server-side configuration for the expected 'Origin' and 'Host' headers within the web server reverse proxy configuration (e.g., nginx or Apache) to drop requests with unauthorized headers.
3. Monitor web server access logs for anomalous 'Origin' header values during password reset requests.
