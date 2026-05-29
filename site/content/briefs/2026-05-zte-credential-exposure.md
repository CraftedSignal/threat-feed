---
title: ZTE H298A/H108N Unauthenticated Credential Exposure
slug: 2026-05-zte-credential-exposure
description: A public exploit (EDB-52592) has been published for ZTE H298A and H108N routers, which allows unauthenticated access to sensitive credentials.
date: "2026-05-29T08:12:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-exposure
  - router
  - exploit
vendors:
  - ZTE
products:
  - H298A
  - H108N
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://www.exploit-db.com/exploits/52592
rules:
  - title: Detect Unauthenticated Access to ZTE Router Credentials
    description: Detects unauthenticated HTTP requests to ZTE H298A/H108N routers that may indicate credential exposure attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect ZTE Router Credential Exposure via Exploit-DB Pattern
    description: Detects HTTP requests containing specific URI stems often associated with credential exposure on ZTE routers, based on Exploit-DB 52592.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A public exploit, EDB-52592, has been released on Exploit-DB detailing an unauthenticated credential exposure vulnerability affecting ZTE H298A and H108N routers. This vulnerability allows an unauthenticated attacker on the local network to retrieve sensitive information, including administrative credentials, from the affected devices. The availability of this exploit increases the likelihood of successful attacks against unpatched devices, as it lowers the barrier to entry for less sophisticated attackers. Defenders should prioritize patching or mitigating this vulnerability to prevent unauthorized access and potential compromise of affected routers and networks.

## Attack Chain

1.  Attacker gains access to the local network where the ZTE H298A/H108N router is located.
2.  Attacker sends a specially crafted HTTP request to the router without authentication.
3.  The router improperly handles the request and exposes sensitive information, including credentials.
4.  Attacker parses the response to extract the administrative username and password.
5.  Attacker uses the obtained credentials to log in to the router's web interface.
6.  Attacker modifies router settings, such as DNS servers or firewall rules.
7.  Attacker can perform man-in-the-middle attacks or redirect traffic to malicious servers.
8.  Attacker gains complete control of the router and can use it as a pivot point to further compromise the network.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain complete control over the affected ZTE routers. This can lead to a variety of malicious activities, including DNS hijacking, man-in-the-middle attacks, and network-wide compromise. Given the prevalence of these routers in home and small business networks, a large number of users are potentially at risk. This could result in data theft, service disruption, and further propagation of malware within the compromised network.

## Recommendation

*   Monitor network traffic for suspicious HTTP requests to ZTE H298A/H108N routers using the provided Sigma rules to detect potential exploitation attempts.
*   Apply available patches or firmware updates from ZTE to address the credential exposure vulnerability.
*   Implement strong password policies and enforce multi-factor authentication where available to mitigate the impact of credential compromise.
*   Segment networks to limit the lateral movement of attackers in case of a successful router compromise.
