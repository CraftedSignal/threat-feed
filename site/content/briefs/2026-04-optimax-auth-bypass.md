---
title: ABB Ability OPTIMAX Authentication Bypass Vulnerability
slug: 2026-04-optimax-auth-bypass
description: CVE-2025-14510 allows an attacker to bypass Azure Active Directory Single-Sign On authentication in vulnerable ABB Ability OPTIMAX versions, potentially granting unauthorized access to critical infrastructure systems.
date: "2026-04-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication bypass
  - ics
  - vulnerability
vendors:
  - ABB
  - Microsoft
products:
  - OPTIMAX 6.1
  - OPTIMAX 6.2
  - OPTIMAX 6.3
  - OPTIMAX 6.4
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1539
    technique_name: Enterprisewide Misconfiguration
cves:
  - id: CVE-2025-14510
    cvss: 8.1
    epss: 0.00031
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-04
  - https://www.cve.org/CVERecord?id=CVE-2025-14510
  - https://search.abb.com/library/Download.aspx?DocumentID=9AKK108472A1331&LanguageCode=en&DocumentPartId=&Action=Launch
  - https://psirt.abb.com/csaf/2026/9akk108472a1331.json
rules:
  - title: Detect Attempts to Access OPTIMAX resources after Failed Azure AD Authentication
    description: This rule detects attempts to access OPTIMAX resources immediately following a failed Azure AD authentication event, which may indicate an authentication bypass attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
  - title: Detect ABB OPTIMAX Unauthenticated Access Attempts
    description: Detects web server logs indicating attempts to access ABB OPTIMAX resources without proper authentication.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2025-14510, affects ABB Ability OPTIMAX versions that utilize Azure Active Directory (Azure AD) for Single-Sign On (SSO) authentication. This flaw stems from an incorrect implementation of the authentication algorithm, potentially allowing attackers to bypass the Azure AD authentication mechanism and gain unauthorized access to the OPTIMAX system. The affected versions include ABB Ability OPTIMAX 6.1 and 6.2 (all versions), 6.3 versions prior to 6.3.1-251120, and 6.4 versions prior to 6.4.1-251120. Successful exploitation could lead to significant disruption in energy, water, and wastewater sectors. The vulnerability was reported to CISA by ABB PSIRT.

## Attack Chain

1.  An attacker identifies an ABB Ability OPTIMAX installation using Azure AD SSO with a vulnerable version (6.1, 6.2, 6.3 < 6.3.1-251120, or 6.4 < 6.4.1-251120).
2.  The attacker crafts a malicious authentication request, exploiting the incorrect implementation of the authentication algorithm (CWE-303).
3.  The crafted request bypasses the expected Azure AD authentication checks within OPTIMAX.
4.  OPTIMAX incorrectly validates the attacker's session, granting them access to the system.
5.  The attacker leverages their unauthorized access to gain control over OPTIMAX functionalities.
6.  The attacker can then modify control parameters, manipulate data, or disrupt operations within the connected industrial processes.

## Impact

Successful exploitation of CVE-2025-14510 enables unauthorized access to ABB Ability OPTIMAX systems, potentially leading to severe consequences in critical infrastructure sectors such as energy, water, and wastewater. An attacker could manipulate industrial processes, disrupt critical services, or cause significant financial and operational damage. Given the widespread deployment of ABB Ability OPTIMAX systems globally, a successful campaign exploiting this vulnerability could have far-reaching impact.

## Recommendation

*   Immediately update ABB Ability OPTIMAX to fixed versions (6.3.1-251120 and later) to remediate CVE-2025-14510.
*   Refer to ABB PSIRT security advisory 9AKK108472A1331 for detailed mitigation steps and recommendations.
*   Minimize network exposure for all control system devices and/or systems, ensuring they are not accessible from the internet, as per CISA's recommended practices.
