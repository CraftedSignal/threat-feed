---
title: Keycloak Vulnerability Allows Data Confidentiality Breach and Security Policy Bypass
slug: 2026-06-keycloak-vuln
description: A vulnerability in Keycloak versions prior to 26.2.14, 26.4.10, and 26.5.5 allows an attacker to cause a breach of data confidentiality and bypass the security policy, as tracked by CVE-2026-2092.
date: "2026-06-01T15:29:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - keycloak
  - data breach
  - security policy bypass
vendors:
  - Keycloak
products:
  - Keycloak (26.2.x)
  - Keycloak (26.4.x)
  - Keycloak (26.5.x)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
cves:
  - id: CVE-2026-2092
    cvss: 7.7
    epss: 0.00105
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0669/
  - https://github.com/keycloak/keycloak/security/advisories/GHSA-794g-x443-36f7
  - https://www.cve.org/CVERecord?id=CVE-2026-2092
rules:
  - title: Detects CVE-2026-2092 Exploitation Attempt — Keycloak Security Policy Bypass
    description: Detects CVE-2026-2092 exploitation attempt — suspicious HTTP requests to Keycloak server that could indicate security policy bypass.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - webserver
  - title: Detects CVE-2026-2092 Exploitation Attempt — Keycloak Data Confidentiality Breach
    description: Detects CVE-2026-2092 exploitation attempt — suspicious HTTP requests to Keycloak server that could lead to data confidentiality breach by checking for unusual request patterns.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability has been discovered in Keycloak, an open-source identity and access management solution. This flaw allows a remote attacker to potentially compromise the confidentiality of data and circumvent security policies implemented within Keycloak. The vulnerability impacts Keycloak versions 26.2.x before 26.2.14, 26.4.x before 26.4.10, and 26.5.x before 26.5.5. Exploitation of this vulnerability could lead to unauthorized access to sensitive information managed by Keycloak, and a weakening of the overall security posture of systems relying on Keycloak for authentication and authorization. The vulnerability is tracked as CVE-2026-2092.

## Attack Chain

1.  Attacker identifies a vulnerable Keycloak instance running a version prior to 26.2.14, 26.4.10, or 26.5.5.
2.  The attacker crafts a malicious request exploiting CVE-2026-2092, targeting a specific endpoint or functionality within Keycloak.
3.  The crafted request bypasses intended security checks or access controls due to the vulnerability.
4.  Successful exploitation allows the attacker to access sensitive data stored or managed by Keycloak, such as user credentials or configuration details.
5.  The attacker leverages the compromised credentials or configuration information to gain unauthorized access to other applications or resources protected by Keycloak.
6.  The attacker escalates privileges within the compromised application or resource, potentially gaining administrative control.
7.  The attacker may exfiltrate sensitive data from the compromised application or resource.
8. The attacker can modify security policies within Keycloak to further their access and evade detection.

## Impact

Successful exploitation of this vulnerability allows for a breach of data confidentiality and a bypass of security policies. An attacker could gain unauthorized access to sensitive user data and resources protected by Keycloak. The number of potential victims depends on the scale of Keycloak deployment, and the sectors targeted could be any that rely on Keycloak for identity and access management. If the attack succeeds, organizations risk data breaches, unauthorized access to critical systems, and a degradation of overall security posture.

## Recommendation

*   Upgrade Keycloak instances to versions 26.2.14, 26.4.10, 26.5.5 or later to remediate CVE-2026-2092, as recommended in the KeyCloak GHSA-794g-x443-36f7 security bulletin.
*   Monitor web server logs for suspicious activity targeting Keycloak endpoints, specifically looking for patterns indicative of exploitation attempts related to CVE-2026-2092.
*   Deploy a web application firewall (WAF) with rules to detect and block exploitation attempts targeting Keycloak.
