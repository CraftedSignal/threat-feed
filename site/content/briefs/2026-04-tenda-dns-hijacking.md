---
title: Tenda Router DNS Hijacking via Cookie Session Weakness
slug: 2026-04-tenda-dns-hijacking
description: Tenda W3002R/A302/W309R routers with firmware V5.07.64_en are vulnerable to unauthenticated DNS hijacking, where attackers exploit a cookie session weakness to modify DNS settings via crafted GET requests.
date: "2026-04-29T20:16:27Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2018-25317
  - dns-hijacking
  - router-vulnerability
vendors:
  - Tenda
products:
  - W3002R/A302/W309R wireless routers
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2018-25317
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25317
  - https://www.exploit-db.com/exploits/44380
  - https://www.vulncheck.com/advisories/tenda-w3002r-a302-w309r-64-en-cookie-session-weakness-dns-change
rules:
  - title: Detect Tenda Router DNS Setting Modification
    description: Detects HTTP requests attempting to modify DNS settings on Tenda routers via the /goform/AdvSetDns endpoint, indicative of CVE-2018-25317 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Crafted Admin Language Cookie in Tenda DNS Modification Requests
    description: Detects HTTP requests to /goform/AdvSetDns with suspicious 'admin language' cookies, potentially indicating an attempt to exploit the cookie session weakness in Tenda routers.
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

Tenda W3002R, A302, and W309R wireless routers running firmware version V5.07.64_en are susceptible to a cookie session weakness (CVE-2018-25317). This vulnerability allows unauthenticated attackers to remotely modify DNS settings on the affected devices. The attack exploits insufficient session validation, enabling malicious actors to inject commands and redirect user traffic to attacker-controlled DNS servers. This poses a significant risk as it can lead to phishing attacks, malware distribution, and credential theft. Exploitation is straightforward, requiring only a crafted HTTP GET request, making it accessible to unsophisticated attackers. The vulnerability was reported in April 2026.

## Attack Chain

1.  An unauthenticated attacker identifies a vulnerable Tenda router with firmware V5.07.64_en.
2.  The attacker crafts an HTTP GET request targeting the `/goform/AdvSetDns` endpoint.
3.  The crafted GET request includes a malicious `admin language` cookie designed to bypass session validation.
4.  The attacker injects modified DNS server addresses into the GET request parameters (primary DNS and secondary DNS).
5.  The vulnerable router processes the malicious GET request without proper session validation.
6.  The router updates its DNS settings to the attacker-specified DNS servers.
7.  Users connected to the compromised router now resolve domain names through the attacker's DNS server.
8.  The attacker can redirect user traffic to malicious websites or intercept sensitive information.

## Impact

Successful exploitation of CVE-2018-25317 allows attackers to perform DNS hijacking on vulnerable Tenda routers, potentially affecting all connected users. By controlling the DNS server, attackers can redirect users to phishing sites, distribute malware, or intercept sensitive communications. Given the ease of exploitation, a large number of routers could be compromised, leading to widespread disruption and data theft. The severity is heightened because no authentication is required to change the DNS settings.

## Recommendation

*   Deploy the Sigma rule `Detect Tenda Router DNS Setting Modification` to monitor web server logs for requests to the `/goform/AdvSetDns` endpoint.
*   Apply network-level filtering to block connections to known malicious DNS servers based on threat intelligence feeds.
*   Although no firmware update is available, consider replacing end-of-life Tenda routers (W3002R/A302/W309R with V5.07.64_en) with more secure models.
