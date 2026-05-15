---
title: Multiple Vulnerabilities in Shibboleth Products Leading to DoS and Security Policy Bypass
slug: 2026-05-shibboleth-vulns
description: Multiple vulnerabilities have been discovered in Shibboleth Identity Provider and OpenSAML Java library that allow an attacker to cause a remote denial of service and security policy bypass, addressed in versions 5.2.2 and later.
date: "2026-05-15T12:23:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:eclipse:jakarta_mail:*:*:*:*:*:*:*:*
  - cpe:2.3:a:eclipse:angus_mail:*:*:*:*:*:*:*:*
tags:
  - shibboleth
  - denial-of-service
  - security-policy-bypass
vendors:
  - Shibboleth
products:
  - Identity Provider
  - OpenSAML Java library
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2025-7962
    cvss: 7.5
    epss: 0.00019
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0597/
  - https://shibboleth.net/community/advisories/secadv_20260513.txt
  - https://shibboleth.net/community/advisories/secadv_20260513a.txt
  - https://shibboleth.net/community/advisories/secadv_20260513b.txt
  - https://www.cve.org/CVERecord?id=CVE-2025-7962
rules:
  - title: Detect CVE-2025-7962 Exploitation Attempt - Suspicious Shibboleth Request
    description: Detects CVE-2025-7962 exploitation attempt targeting Shibboleth applications by monitoring for suspicious request patterns in web server logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
  - title: Detect Shibboleth Denial of Service Attempt - High Request Rate to Shibboleth Endpoints
    description: Detects potential denial-of-service (DoS) attacks against Shibboleth Identity Provider by monitoring for abnormally high request rates to known Shibboleth endpoints.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 2
---

Multiple vulnerabilities have been identified in Shibboleth Identity Provider and OpenSAML Java library products. These vulnerabilities can be exploited by an attacker to trigger a remote denial of service (DoS) condition and bypass security policies. The vulnerabilities affect Identity Provider and OpenSAML Java library versions prior to 5.2.2. Successful exploitation could lead to disruptions in services relying on Shibboleth for authentication and authorization, potentially impacting access to critical resources. The vendor has released security advisories to address these issues, urging users to apply the necessary patches to mitigate the risks.

## Attack Chain

1.  An attacker identifies a vulnerable Shibboleth Identity Provider or OpenSAML Java library instance running a version prior to 5.2.2.
2.  The attacker crafts a malicious request designed to exploit CVE-2025-7962 or other vulnerabilities.
3.  The malicious request is sent to the vulnerable Shibboleth component, potentially targeting a specific endpoint or function.
4.  The vulnerable component processes the request, triggering a denial-of-service condition or a security policy bypass.
5.  In a DoS attack, the server becomes unresponsive due to resource exhaustion, preventing legitimate users from accessing services.
6.  In a security policy bypass, the attacker gains unauthorized access to protected resources or functionalities.
7.  The attacker leverages the bypass to perform actions they are not authorized to do.
8.  The attacker may further compromise the system or network, depending on the scope of the bypassed security policy.

## Impact

Successful exploitation of these vulnerabilities could result in a denial of service, disrupting authentication and authorization services for users relying on Shibboleth. A security policy bypass could grant unauthorized access to sensitive resources and functionalities, potentially leading to data breaches or further system compromise. These vulnerabilities affect Identity Provider and OpenSAML Java library versions prior to 5.2.2.

## Recommendation

*   Upgrade Shibboleth Identity Provider and OpenSAML Java library to version 5.2.2 or later to remediate the vulnerabilities described in the vendor's security advisories (https://shibboleth.net/community/advisories/secadv_20260513.txt, https://shibboleth.net/community/advisories/secadv_20260513a.txt, https://shibboleth.net/community/advisories/secadv_20260513b.txt).
*   Monitor web server logs for suspicious activity and requests targeting Shibboleth endpoints, using webserver logs.
*   Implement rate limiting and input validation to mitigate potential denial-of-service attacks and security policy bypass attempts.
