---
title: EventON Action User Plugin Authorization Bypass in WordPress
slug: 2026-07-eventon-auth-bypass
description: An authorization bypass vulnerability (CVE-2026-10033) in the EventON Action User plugin for WordPress, affecting all versions up to and including 2.5.14, allows unauthenticated attackers to grant EventON management and file upload capabilities to non-administrator users, enumerate WordPress users, and tamper with event-to-user assignments, leading to privilege escalation.
date: "2026-07-24T10:17:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - privilege-escalation
  - wordpress-plugin
  - web-application
  - cve
vendors:
  - EventON
  - WordPress
products:
  - EventON Action User plugin <= 2.5.14
  - WordPress
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for unauthenticated attackers to grant EventON management capabilities and the upload_files capability to any non-administrator WordPress role or user, escalating their privileges within the site.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: the same unauthenticated exposure also allows attackers to enumerate all WordPress users with their IDs and display names
    confidence_band: high
cves:
  - id: CVE-2026-10033
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10033
---

The EventON Action User plugin for WordPress, across all versions up to and including 2.5.14, is affected by an authorization bypass vulnerability identified as CVE-2026-10033. This flaw stems from inadequate verification of user authorization when performing specific actions within the plugin. Unauthenticated attackers can leverage this vulnerability to grant EventON management and file upload capabilities to any non-administrator WordPress role or individual user, effectively escalating privileges within the compromised site. The vulnerability also enables attackers to enumerate WordPress users, including their IDs and display names, disclose role and user capability states, and tamper with event-to-user assignments. This exposes sensitive information and allows for significant control over the EventON plugin's features.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site utilizing the vulnerable EventON Action User plugin (versions up to and including 2.5.14).
2. The attacker sends a specially crafted HTTP request, exploiting the authorization bypass, to a plugin-related endpoint on the WordPress site.
3. This request manipulates internal plugin functions responsible for managing user roles and capabilities, bypassing proper authentication and authorization checks due to insufficient verification.
4. The attacker successfully modifies the capabilities of a targeted non-administrator WordPress user or role, granting them elevated permissions such as EventON management and the `upload_files` capability.
5. With these escalated privileges, the attacker can then upload malicious files or gain unauthorized control over EventON functionalities within the WordPress environment.
6. Concurrently or independently, the attacker sends further crafted requests to enumerate all WordPress users, retrieving their IDs and display names.
7. Additional unauthenticated requests allow the disclosure of role and user capability states, along with sensitive nonce values.
8. The attacker achieves unauthorized privilege escalation and information disclosure, enabling further malicious activities on the compromised WordPress site.

## Impact

Successful exploitation of CVE-2026-10033 allows unauthenticated attackers to significantly escalate their privileges within a targeted WordPress site. This includes granting themselves or other non-administrator users the ability to upload files and manage EventON features, which could lead to arbitrary code execution or website defacement. The ability to enumerate all WordPress user IDs, display names, and disclose capability states also presents a critical information disclosure risk, potentially aiding further targeted attacks or account compromise. No specific victim counts or industry sectors have been publicly identified, but any WordPress site running the vulnerable plugin is at risk.

## Recommendation

- Immediately upgrade the EventON Action User plugin to a version greater than 2.5.14 to mitigate CVE-2026-10033.
- Monitor web server access logs for unusual HTTP POST or GET requests to EventON-related endpoints that attempt to modify user roles or capabilities, or enumerate users (log source: `webserver`).
- Enable logging for all WordPress user role and capability modifications, and regularly review these logs for unauthorized changes (log source: `webserver`, `application_logs` for WordPress specific actions).
- Consider implementing a Web Application Firewall (WAF) to detect and block suspicious requests targeting known WordPress vulnerabilities.
