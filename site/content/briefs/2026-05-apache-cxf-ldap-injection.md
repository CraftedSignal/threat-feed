---
title: 'CVE-2026-44930: Apache CXF LDAP Injection Vulnerability'
slug: 2026-05-apache-cxf-ldap-injection
description: CVE-2026-44930 is an LDAP injection vulnerability in the LDAP Certificate repository of the XKMS server in Apache CXF that may allow an attacker to retrieve arbitrary certificates from the repository.
date: "2026-05-26T13:52:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:apache:cxf:*:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:cxf:4.2.0:*:*:*:*:*:*:*
tags:
  - ldap-injection
  - cve
  - web-application
vendors:
  - Apache
products:
  - CXF
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-44930
    cvss: 9.8
    epss: 0.00017
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44930
  - https://lists.apache.org/thread/c1zqxppo1m5z3kbdhjn5p991zk09ynkh
  - http://www.openwall.com/lists/oss-security/2026/05/22/9
rules:
  - title: Detects CVE-2026-44930 Exploitation — Malicious LDAP Query
    description: Detects CVE-2026-44930 exploitation — suspicious LDAP-related requests containing injection attempts
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-44930 Exploitation — LDAP URI in HTTP Request
    description: Detects CVE-2026-44930 exploitation — HTTP requests containing an LDAP URI indicating potential injection
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

An LDAP injection vulnerability exists within the LDAP Certificate repository of the XKMS server in Apache CXF. This flaw, identified as CVE-2026-44930, potentially allows a remote attacker to inject malicious LDAP queries. Successful exploitation could lead to the unauthorized retrieval of arbitrary certificates from the repository. The vulnerability affects Apache CXF versions prior to 4.2.1, 4.1.6, and 3.6.11. Organizations using Apache CXF should upgrade to the patched versions to mitigate this risk.

## Attack Chain

1.  Attacker identifies an Apache CXF server with an exposed XKMS service using the LDAP Certificate repository.
2.  The attacker crafts a malicious LDAP query string containing injection payloads.
3.  The attacker sends a request to the vulnerable XKMS endpoint, embedding the malicious LDAP query.
4.  The Apache CXF server processes the request and constructs an LDAP query using the attacker-supplied input without proper sanitization.
5.  The crafted LDAP query is executed against the LDAP server.
6.  Due to the LDAP injection vulnerability, the attacker is able to bypass intended access controls.
7.  The attacker retrieves sensitive certificate data from the LDAP server that they are not authorized to access.

## Impact

Successful exploitation of CVE-2026-44930 can lead to the unauthorized disclosure of sensitive information, specifically the arbitrary certificates stored within the LDAP repository. The impact of this vulnerability is significant as compromised certificates can be used for identity spoofing, man-in-the-middle attacks, and other malicious activities. Organizations utilizing affected versions of Apache CXF are at risk of having their certificate data exposed.

## Recommendation

*   Upgrade to Apache CXF versions 4.2.1, 4.1.6, or 3.6.11 to remediate the LDAP injection vulnerability as advised in the advisory ([https://lists.apache.org/thread/c1zqxppo1m5z3kbdhjn5p991zk09ynkh](https://lists.apache.org/thread/c1zqxppo1m5z3kbdhjn5p991zk09ynkh)).
*   Deploy the Sigma rule "Detects CVE-2026-44930 Exploitation — Malicious LDAP Query" to identify potential exploitation attempts.
*   Monitor web server logs for unusual LDAP-related requests targeting the XKMS service.
