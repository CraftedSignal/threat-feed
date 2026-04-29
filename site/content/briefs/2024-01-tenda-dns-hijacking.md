---
title: Tenda FH303/A300 DNS Hijacking Vulnerability (CVE-2018-25318)
slug: 2024-01-tenda-dns-hijacking
description: Tenda FH303/A300 firmware V5.07.68_EN contains a session weakness vulnerability (CVE-2018-25318) that allows unauthenticated attackers to modify DNS settings by exploiting insufficient cookie validation, potentially redirecting user traffic to malicious sites.
date: "2024-01-03T18:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2018-25318
  - tenda
  - dns-hijacking
  - network
vendors:
  - Tenda
products:
  - FH303/A300 firmware
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2018-25318
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25318
rules:
  - title: Detect Tenda Router DNS Hijacking Attempt
    description: Detects attempts to exploit CVE-2018-25318 by monitoring for suspicious requests to the /goform/AdvSetDns endpoint with DNS modification parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthenticated DNS Modification on Tenda Router
    description: Detects suspicious activity related to DNS settings modification on Tenda routers, focusing on POST requests without proper authentication headers.
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

CVE-2018-25318 affects Tenda FH303/A300 routers running firmware version V5.07.68_EN. This vulnerability stems from a session weakness related to insufficient cookie validation. An unauthenticated attacker can exploit this flaw to modify the DNS settings of the router. By sending a crafted GET request to the `/goform/AdvSetDns` endpoint, an attacker can inject a malicious admin cookie. This allows them to overwrite the configured DNS servers, potentially redirecting all network traffic from connected devices through attacker-controlled infrastructure. This can lead to phishing attacks, malware distribution, and other malicious activities. The vulnerability poses a significant risk to home and small office networks using the affected Tenda routers.

## Attack Chain

1. An attacker identifies a vulnerable Tenda FH303/A300 router running firmware V5.07.68_EN.
2. The attacker crafts a malicious HTTP GET request targeting the `/goform/AdvSetDns` endpoint.
3. The crafted GET request includes a forged admin cookie, bypassing authentication checks due to the session weakness.
4. The attacker sends the crafted GET request to the router's management interface.
5. The router, due to insufficient cookie validation, accepts the forged cookie and processes the request.
6. The request modifies the DNS server settings on the router, replacing the legitimate DNS servers with attacker-controlled DNS servers.
7. Users connected to the router unknowingly use the attacker's DNS servers for name resolution.
8. DNS requests are redirected to malicious IPs controlled by the attacker, potentially leading to phishing sites or malware downloads.

## Impact

Successful exploitation of CVE-2018-25318 allows an attacker to perform DNS hijacking on affected Tenda routers. This can redirect users to malicious websites designed to steal credentials, distribute malware, or conduct other harmful activities. The vulnerability poses a critical risk to users of the affected routers, as it can compromise their online security and privacy. The CVSS v3.1 base score for this vulnerability is 9.8, highlighting its severity. The number of affected users is dependent on the number of deployed vulnerable devices.

## Recommendation

*   Monitor web server logs for requests to `/goform/AdvSetDns` with unusual parameters (Sigma rule: "Detect Tenda Router DNS Hijacking Attempt").
*   If possible, upgrade the router firmware to a version that patches CVE-2018-25318.
*   Implement network segmentation to limit the impact of compromised devices.
*   Consider using a reputable DNS service with built-in security features to mitigate the impact of DNS hijacking attacks.
