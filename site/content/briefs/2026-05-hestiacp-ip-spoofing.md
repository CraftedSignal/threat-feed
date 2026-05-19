---
title: HestiaCP IP Spoofing Vulnerability (CVE-2026-43634)
slug: 2026-05-hestiacp-ip-spoofing
description: HestiaCP versions 1.2.0 through 1.9.4 are vulnerable to IP spoofing (CVE-2026-43634), allowing unauthenticated remote attackers to bypass authentication security controls by manipulating the CF-Connecting-IP HTTP header to circumvent fail2ban, bypass IP allowlists, and poison authentication logs.
date: "2026-05-19T15:19:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ip-spoofing
  - authentication-bypass
  - cve
vendors:
  - HestiaCP
products:
  - HestiaCP (1.2.0 - 1.9.4)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-43634
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43634
rules:
  - title: Detect HestiaCP IP Spoofing via CF-Connecting-IP Header
    description: Detects CVE-2026-43634 exploitation — HTTP requests with CF-Connecting-IP header, indicating potential IP spoofing attempt in HestiaCP.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect HestiaCP Authentication Log Manipulation
    description: Detects potential authentication log manipulation in HestiaCP by monitoring for authentication events originating from unexpected CF-Connecting-IP addresses.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

HestiaCP, a popular open-source hosting control panel, is vulnerable to IP address spoofing in versions 1.2.0 through 1.9.4. This vulnerability, identified as CVE-2026-43634, enables unauthenticated remote attackers to forge the source IP address of HTTP requests by injecting an arbitrary IP address into the `CF-Connecting-IP` HTTP header. This header is intended to be used when HestiaCP is deployed behind Cloudflare, but the application fails to validate that the request indeed originated from Cloudflare's network. By exploiting this flaw, attackers can bypass security measures like fail2ban's brute-force protection, circumvent per-user IP address allowlists, and manipulate authentication audit logs. The lack of proper validation on this header presents a significant risk to the integrity and security of HestiaCP installations.

## Attack Chain

1.  The attacker identifies a vulnerable HestiaCP instance running versions 1.2.0 through 1.9.4.
2.  The attacker crafts a malicious HTTP request targeting an authentication endpoint (e.g., login page).
3.  The attacker adds the `CF-Connecting-IP` header to the HTTP request, setting its value to a desired, spoofed IP address (e.g., a trusted IP or a local address).
4.  The attacker sends the crafted HTTP request to the vulnerable HestiaCP server.
5.  HestiaCP incorrectly uses the spoofed IP address from the `CF-Connecting-IP` header for authentication checks and logging.
6.  The attacker circumvents fail2ban's brute-force protection, as the repeated failed login attempts appear to originate from the spoofed IP address, which may be whitelisted or otherwise ignored by fail2ban.
7.  The attacker bypasses per-user IP address allowlists if the spoofed IP matches an allowed IP address for the target user.
8.  The attacker successfully authenticates or performs privileged actions, while the authentication logs record the spoofed IP address, hindering accurate auditing and incident response.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass critical security controls, potentially leading to unauthorized access to sensitive data and system resources. By circumventing fail2ban, attackers can perform brute-force attacks without being blocked. Bypassing IP address allowlists grants unauthorized access to restricted areas of the control panel. Furthermore, by poisoning authentication logs, attackers can cover their tracks and complicate incident investigations. This could affect any HestiaCP instance running versions 1.2.0 to 1.9.4, potentially impacting thousands of servers and their hosted websites.

## Recommendation

*   Deploy the Sigma rule "Detect HestiaCP IP Spoofing via CF-Connecting-IP Header" to identify attempts to exploit CVE-2026-43634 in your environment.
*   Apply available patches or upgrade HestiaCP instances to a version beyond 1.9.4 to remediate CVE-2026-43634.
*   Inspect web server access logs for HTTP requests containing the `CF-Connecting-IP` header and investigate any anomalies, correlating with authentication failures or suspicious activity.
*   Implement server-side validation to ensure that the `CF-Connecting-IP` header only contains IP addresses originating from legitimate Cloudflare infrastructure, based on their published IP ranges.
*   Use the provided information on affected products and versions to prioritize patching efforts.
