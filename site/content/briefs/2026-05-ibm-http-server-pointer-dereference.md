---
title: 'CVE-2026-8835: IBM HTTP Server Invalid Pointer Dereference Vulnerability'
slug: 2026-05-ibm-http-server-pointer-dereference
description: IBM HTTP Server versions 8.5 and 9.0 are susceptible to an invalid pointer dereference, potentially allowing a privileged, authenticated user to expose sensitive information or cause a denial of service.
date: "2026-05-26T18:19:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - pointer dereference
  - dos
  - information disclosure
vendors:
  - IBM
products:
  - HTTP Server 8.5
  - HTTP Server 9.0
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-8835
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8835
  - https://www.ibm.com/support/pages/node/7274065
rules:
  - title: Detect CVE-2026-8835 Exploitation Attempt
    description: Detects CVE-2026-8835 exploitation attempt — Monitor for abnormal requests potentially triggering the invalid pointer dereference.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - webserver
  - title: Detect High Volume of Errors from IBM HTTP Server
    description: Detects a potential Denial of Service by monitoring the rate of 500 errors from IBM HTTP Server. A sudden spike may indicate an exploit attempt
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 2
---

IBM HTTP Server versions 8.5 and 9.0 are vulnerable to an invalid pointer dereference vulnerability, identified as CVE-2026-8835. This flaw could be exploited by a privileged user who has been authenticated to the Administration Server. Successful exploitation of this vulnerability could result in the exposure of sensitive information or a denial of service (DoS) condition. The vulnerability was reported to IBM and assigned a CVSS v3.1 base score of 7.3, indicating a high severity level. Defenders should apply appropriate mitigations to prevent potential exploitation by malicious actors.

## Attack Chain

1.  Attacker gains privileged access to the IBM HTTP Server's Administration Server, likely via compromised credentials or an insider threat.
2.  Attacker authenticates to the Administration Server using their privileged credentials.
3.  Attacker crafts a malicious request targeting a specific function vulnerable to pointer dereference.
4.  The malicious request triggers the invalid pointer dereference within the IBM HTTP Server code.
5.  The server attempts to access an invalid memory address, leading to either information disclosure or a crash.
6.  If information disclosure occurs, the attacker may gain access to sensitive data such as configuration files, user credentials, or internal system information.
7.  If a crash occurs, the server experiences a denial of service, impacting availability for legitimate users.

## Impact

Successful exploitation of CVE-2026-8835 could lead to the exposure of sensitive information, potentially including configuration details or credentials, which could be used for further attacks. Alternatively, the vulnerability can be exploited to cause a denial of service, disrupting normal operations of web applications served by the affected IBM HTTP Server. The impact is limited to authenticated privileged users, reducing the scope of potential attackers.

## Recommendation

*   Apply the security patch or upgrade to a non-vulnerable version of IBM HTTP Server as described in the IBM advisory [https://www.ibm.com/support/pages/node/7274065].
*   Monitor access logs for suspicious activity originating from privileged user accounts, focusing on requests to sensitive administrative endpoints.
*   Deploy the Sigma rule "Detect CVE-2026-8835 Exploitation Attempt" to identify potential exploitation attempts based on abnormal requests.
