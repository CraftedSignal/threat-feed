---
title: Grav API Plugin Missing Authorization Allows Security Settings Modification
slug: 2026-07-grav-api-auth-bypass
description: Grav API Plugin versions prior to 1.0.10 contain a missing authorization vulnerability (CVE-2026-65895) allowing authenticated users with the 'api.config.write' privilege to modify critical security settings, including disabling site-wide rate limiting to enable credential brute-forcing attacks and reconfiguring CORS policies to include attacker-controlled origins with credentials enabled, potentially leading to unauthorized data access.
date: "2026-07-23T12:22:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - grav-cms
  - api-plugin
  - vulnerability
  - access-control
  - cwe-862
vendors:
  - Grav
products:
  - Grav API Plugin (versions before 1.0.10)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Attackers can disable rate limiting site-wide to enable credential brute-forcing attacks
    confidence_band: high
cves:
  - id: CVE-2026-65895
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65895
  - https://github.com/getgrav/grav/commit/f9438d4e71389b1041ac60b69b0b5714ecfa3bdd
  - https://github.com/getgrav/grav/security/advisories/GHSA-4pqv-2qj5-38fp
  - https://www.vulncheck.com/advisories/grav-api-plugin-before-broken-access-control
---

CVE-2026-65895 identifies a critical missing authorization vulnerability within Grav API Plugin versions prior to 1.0.10. This flaw allows authenticated users who possess the `api.config.write` privilege to bypass intended access controls and modify security-critical configurations. Specifically, an attacker can disable the site's rate limiting feature, paving the way for credential brute-forcing attacks. Furthermore, the vulnerability enables the modification of Cross-Origin Resource Sharing (CORS) policies, allowing an attacker to include their own controlled origins with credentials enabled. This manipulation can lead to unauthorized access to sensitive data and credentials, impacting the integrity and confidentiality of the Grav installation and its users. The vulnerability carries a CVSS v3.1 Base Score of 8.5 (High), emphasizing its significant potential impact.

## Attack Chain

1. An attacker gains authenticated access to a Grav instance, potentially through compromised credentials or other means.
2. The attacker's account possesses the `api.config.write` privilege, which is overly broad due to CVE-2026-65895 and allows modification of critical settings.
3. The attacker crafts and sends an API request to the Grav instance, targeting the rate limiting configuration endpoint.
4. Leveraging the missing authorization vulnerability, the attacker successfully disables site-wide rate limiting, bypassing intended security restrictions.
5. Subsequently, the attacker sends another API request to reconfigure the Cross-Origin Resource Sharing (CORS) policies of the Grav instance.
6. The attacker adds attacker-controlled origins to the CORS policy, enabling the inclusion of credentials and circumventing the browser's same-origin policy.
7. With rate limiting disabled, the attacker can now perform high-volume credential brute-forcing attempts against other user accounts on the Grav instance.
8. The manipulated CORS policies facilitate unauthorized access to sensitive data and credentials from victim browsers interacting with the compromised Grav instance.

## Impact

If successfully exploited, CVE-2026-65895 enables severe consequences for affected Grav instances. The ability to disable rate limiting allows attackers to launch efficient, high-volume credential brute-forcing attacks, potentially leading to the compromise of additional user accounts. Reconfiguring CORS policies permits unauthorized cross-origin requests, leading to data exfiltration, session hijacking, and other web-based attacks that compromise the confidentiality of user information. The vulnerability could result in widespread account compromise and unauthorized data access across the platform.

## Recommendation

* Patch Grav API Plugin immediately to version 1.0.10 or later to address CVE-2026-65895.
* Review Grav access control policies to ensure that only trusted administrators have the `api.config.write` privilege.
* Monitor Grav API logs for any unauthorized or suspicious modifications to rate limiting and CORS configuration settings.
