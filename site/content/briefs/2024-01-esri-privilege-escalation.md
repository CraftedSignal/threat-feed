---
title: Esri Portal for ArcGIS Privilege Escalation via CVE-2026-33518
slug: 2024-01-esri-privilege-escalation
description: Esri Portal for ArcGIS 11.5 on Windows and Linux is vulnerable to privilege escalation (CVE-2026-33518), allowing highly privileged users to create developer credentials with excessive permissions.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - esri
  - arcgis
  - privilege-escalation
  - CVE-2026-33518
  - vulnerability
vendors:
  - Esri
products:
  - Portal for ArcGIS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-33518
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33518
rules:
  - title: Detect ArcGIS Portal Excessive Developer Credential Creation
    description: Detects the creation of developer credentials within Esri Portal for ArcGIS, which may indicate exploitation of CVE-2026-33518.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-33518
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect ArcGIS Portal Authentication using Newly Created Developer Credentials
    description: Detects authentication attempts using developer credentials shortly after their creation, which may indicate exploitation of CVE-2026-33518.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-33518
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Esri Portal for ArcGIS 11.5, running on both Windows and Linux platforms, is susceptible to an incorrect privilege assignment vulnerability identified as CVE-2026-33518. This flaw enables users with elevated privileges within the ArcGIS portal to generate developer credentials that inadvertently grant broader permissions than intended. This vulnerability, if exploited, could lead to unauthorized access to sensitive resources, data breaches, and compromise of the entire ArcGIS environment. Successful exploitation could allow an attacker to perform administrative actions beyond their intended scope, potentially impacting data integrity and system availability.

## Attack Chain

1. A highly privileged user authenticates to the Esri Portal for ArcGIS 11.5.
2. The user navigates to the developer credential creation interface within the portal.
3. The user provides the necessary inputs to create a new developer credential.
4. Due to the vulnerability (CVE-2026-33518), the credential creation process incorrectly assigns excessive privileges to the newly created credential.
5. The attacker uses the newly created developer credentials to authenticate to the ArcGIS portal.
6. The attacker leverages the excessive privileges to access restricted resources, such as sensitive data or administrative functions.
7. The attacker performs unauthorized actions, potentially modifying data, creating new user accounts, or changing system configurations.

## Impact

Successful exploitation of CVE-2026-33518 allows attackers to perform actions beyond their intended authorization level. This can lead to data breaches, unauthorized modification of GIS data, and disruption of services. The lack of proper privilege assignment opens the door for malicious actors to gain control over sensitive resources, compromise data integrity, and escalate their access to critical system components within the Esri ArcGIS environment. The impact can range from data theft to complete system compromise.

## Recommendation

*   Apply the patch or upgrade to a non-vulnerable version of Esri Portal for ArcGIS to remediate CVE-2026-33518, once available from the vendor.
*   Implement the "Detect ArcGIS Portal Excessive Developer Credential Creation" Sigma rule to detect suspicious developer credential creation activity.
*   Review and audit existing ArcGIS user accounts and their assigned privileges to identify and correct any over-provisioned access rights.
*   Monitor Esri Portal for ArcGIS logs for unusual account activity or privilege escalations.
