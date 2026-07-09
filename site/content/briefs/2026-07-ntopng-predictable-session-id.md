---
title: 'CVE-2026-38968: ntopng Predictable Session Identifier Vulnerability Leading to Session Hijacking'
slug: 2026-07-ntopng-predictable-session-id
description: CVE-2026-38968 affects ntopng versions up to 6.6, enabling session hijacking through predictable session identifiers generated with weak time-seeded pseudo-randomness in `src/HTTPserver.cpp`, allowing attackers to gain unauthorized access to legitimate user sessions.
date: "2026-07-09T07:44:17Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:ntop:ntopng:*:*:*:*:*:*:*:*
tags:
  - session-hijacking
  - vulnerability
  - ntopng
  - network-monitoring
vendors:
  - ntop
products:
  - ntopng through 6.6
cves:
  - id: CVE-2026-38968
    cvss: 9.8
    epss: 0.00379
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-38968
---

A critical vulnerability, CVE-2026-38968, has been identified in ntopng versions through 6.6, allowing for predictable session identifiers and subsequent session hijacking. The flaw resides in `src/HTTPserver.cpp`, where the HTTP session creation process relies on weak time-seeded pseudo-randomness to generate session cookies. This implementation weakness can result in deterministic or colliding session cookies, especially under specific timing conditions or attacker influence. For defenders, this vulnerability is significant as it permits an attacker to impersonate legitimate, authenticated users, potentially leading to unauthorized access to sensitive network monitoring data, configuration changes, or further lateral movement within an environment. No specific threat actor or active exploitation campaign has been publicly reported at the time of disclosure, but the nature of the vulnerability makes it highly attractive for attackers targeting network infrastructure.

## Attack Chain

1. An attacker targets a vulnerable ntopng instance (version 6.6 or earlier) and prepares to observe or predict session ID generation.
2. A legitimate user authenticates to the ntopng web interface, triggering the creation of a new HTTP session by the vulnerable server.
3. The ntopng server, specifically the code in `src/HTTPserver.cpp`, uses weak time-seeded pseudo-randomness to generate a session cookie for the legitimate user.
4. Due to the predictability of the session identifier generation, the attacker can either predict a valid session ID or observe enough session generation patterns to create a collision.
5. The attacker crafts an HTTP request, including a predicted or colliding session cookie, and sends it to the ntopng server.
6. The ntopng server validates the attacker's session cookie as legitimate, thereby granting the attacker unauthorized access to the application with the privileges of the hijacked user.
7. The attacker can now perform actions on behalf of the legitimate user, such as viewing network statistics, modifying configurations, or creating new users, without proper authentication.

## Impact

The successful exploitation of CVE-2026-38968 results in unauthorized access to the ntopng web interface. Attackers can hijack legitimate user sessions, gaining the same level of access and control as the compromised user. Depending on the privileges of the hijacked account, this could lead to sensitive network data exfiltration, unauthorized modification of network monitoring configurations, or disruption of network visibility. If an administrative user session is compromised, the attacker could take full control of the ntopng instance, potentially impacting network security and operational integrity. No specific victim counts or targeted sectors have been disclosed in connection with this vulnerability, but any organization using vulnerable ntopng versions is at risk.

## Recommendation

* Immediately update ntopng installations to a patched version beyond 6.6 to remediate CVE-2026-38968.
* Implement strong session management practices and consider adding a Web Application Firewall (WAF) to detect and block abnormal session cookie patterns that could indicate exploitation attempts against CVE-2026-38968.
* Enable comprehensive logging for web server access and application-level events on ntopng servers, then review logs for unusual authentication attempts or session activities potentially linked to CVE-2026-38968.
