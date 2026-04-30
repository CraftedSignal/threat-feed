---
title: Tenda W308R DNS Hijacking Vulnerability (CVE-2018-25316)
slug: 2026-04-tenda-dns-hijack
description: Tenda W308R v2 V5.07.48 is vulnerable to cookie session weakness, allowing unauthenticated attackers to modify DNS settings via crafted GET requests to redirect user traffic to malicious sites.
date: "2026-04-29T20:16:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2018-25316
  - dns-hijacking
  - tenda
  - cookie-injection
vendors:
  - Tenda
products:
  - W308R v2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2018-25316
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25316
  - https://www.exploit-db.com/exploits/44373
  - https://www.vulncheck.com/advisories/tenda-w308r-v2-cookie-session-weakness-dns-change
rules:
  - title: Detect Tenda Router DNS Hijack Attempt
    description: Detects suspicious requests to the /goform/AdvSetDns endpoint with a crafted cookie, indicating a potential DNS hijack attempt on Tenda W308R v2 routers.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda Router Admin Language Cookie
    description: Detects web requests with a suspicious 'admin language' cookie, potentially indicating an attempt to exploit the Tenda router vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Tenda W308R v2 running firmware V5.07.48 is susceptible to a cookie session weakness (CVE-2018-25316) that enables unauthenticated attackers to perform DNS hijacking. This vulnerability stems from insufficient session validation. An attacker can exploit this weakness by sending specially crafted GET requests to the `goform/AdvSetDns` endpoint. The malicious request includes a crafted admin language cookie, which bypasses authentication checks and allows modification of the device's DNS server settings. Successful exploitation allows the attacker to redirect the router's DNS queries to a malicious server under their control. This poses a significant risk to end-users, as it can lead to phishing attacks, malware distribution, and other malicious activities.

## Attack Chain

1. The attacker identifies a vulnerable Tenda W308R v2 router running firmware V5.07.48 exposed to the internet.
2. The attacker crafts a malicious HTTP GET request targeting the `goform/AdvSetDns` endpoint.
3. The GET request includes a crafted "admin language cookie" designed to bypass authentication.
4. The router receives the malicious GET request and, due to insufficient session validation, incorrectly authenticates the attacker.
5. The router processes the malicious request, modifying the DNS server settings to attacker-controlled DNS servers.
6. Users connected to the compromised router now resolve domain names through the attacker's DNS server.
7. The attacker's DNS server redirects users to malicious websites, potentially serving malware or phishing pages.
8. Users unknowingly interact with the malicious content, leading to data theft, system compromise, or other harmful outcomes.

## Impact

Successful exploitation of this vulnerability allows an attacker to control DNS resolution for all devices connected to the affected Tenda W308R v2 router. This can lead to widespread redirection to phishing sites designed to steal credentials, or to sites hosting malware that infects user devices. Given the widespread use of Tenda routers, this vulnerability could impact a large number of home and small business networks. A successful attack allows the attacker to perform man-in-the-middle attacks, eavesdrop on network traffic, and compromise connected devices.

## Recommendation

*   Deploy the Sigma rule `Detect Tenda Router DNS Hijack Attempt` to identify attempts to exploit this vulnerability by monitoring for suspicious requests to the `/goform/AdvSetDns` endpoint (log source: webserver).
*   Monitor web server logs for requests containing a crafted admin language cookie to the `/goform/AdvSetDns` endpoint, indicating potential exploitation attempts (log source: webserver).
*   Apply available patches or firmware updates from Tenda to address the cookie session weakness and prevent unauthorized DNS modifications.
*   Consider replacing the affected device if a patch is unavailable, especially in high-risk environments.
