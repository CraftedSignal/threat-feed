---
title: ZTE ZXHN H188A Unauthenticated Credential Disclosure (CVE-2026-34472)
slug: 2024-01-03-zte-zxhn-credential-disclosure
description: CVE-2026-34472 allows unauthenticated attackers on the local network to retrieve sensitive credentials from vulnerable ZTE ZXHN H188A routers via the web management interface, potentially leading to unauthorized access and control.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - credential-access
  - router
  - zte
  - cve-2026-34472
vendors:
  - ZTE
products:
  - ZXHN H188A
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34472
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect ZTE ZXHN H188A Credential Disclosure Attempt
    description: Detects attempts to exploit the unauthenticated credential disclosure vulnerability (CVE-2026-34472) in ZTE ZXHN H188A routers by monitoring suspicious HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to ZTE ZXHN H188A Web Interface from Unusual Source IP
    description: Detects access to the ZTE ZXHN H188A web interface from a source IP address that is not normally seen accessing the device.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-34472 is a critical vulnerability affecting ZTE ZXHN H188A routers, specifically versions V6.0.10P2_TE and V6.0.10P3N3_TE. This vulnerability allows an unauthenticated attacker on the local network to access sensitive information, including the default administrator password, WLAN PSK, and PPPoE credentials. The vulnerability resides within the router's web management interface and arises from insufficient access controls. Successful exploitation grants attackers the ability to potentially perform configuration changes without authentication, leading to a complete compromise of the device and connected network. Defenders need to prioritize detection and mitigation of this vulnerability to prevent unauthorized access and potential data breaches.

## Attack Chain

1. The attacker gains access to the local network where the vulnerable ZTE ZXHN H188A router is connected.
2. The attacker sends a crafted HTTP request to the router's web management interface on port 80 or 443.
3. The vulnerable router processes the request without proper authentication checks.
4. The router discloses sensitive information, including the default administrator password, WLAN PSK, and PPPoE credentials, in the HTTP response.
5. The attacker uses the obtained administrator password to log into the web management interface.
6. The attacker modifies router settings, such as DNS servers, firewall rules, or WLAN configurations.
7. The attacker intercepts network traffic or redirects users to malicious websites.
8. The attacker gains complete control over the router and the connected network.

## Impact

Successful exploitation of CVE-2026-34472 allows attackers to gain complete control over the vulnerable ZTE ZXHN H188A router and the connected network. This could lead to data breaches, malware infections, and denial-of-service attacks. Given the potential for unauthorized access and control, this vulnerability poses a significant risk to both home and small business networks. The number of affected devices and networks is currently unknown, but the widespread use of these routers suggests a potentially large attack surface.

## Recommendation

*   Deploy the Sigma rule `Detect ZTE ZXHN H188A Credential Disclosure Attempt` to your SIEM to detect suspicious HTTP requests targeting the router's web management interface.
*   Disable remote access to the router's web management interface to reduce the attack surface.
*   If possible, replace the vulnerable ZTE ZXHN H188A router with a more secure model.
*   Monitor network traffic for unusual DNS queries or connections to suspicious IP addresses after applying this patch using network_connection and dns_query logs.
