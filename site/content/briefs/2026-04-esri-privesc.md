---
title: Esri Portal for ArcGIS Incorrect Authorization Vulnerability (CVE-2026-33519)
slug: 2026-04-esri-privesc
description: CVE-2026-33519 is a critical vulnerability in Esri Portal for ArcGIS 11.4, 11.5, and 12.0, where incorrect authorization checks on developer credentials can lead to unauthorized privilege escalation on Windows, Linux, and Kubernetes deployments.
date: "2026-04-21T21:16:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - esri
  - arcgis
  - privilege-escalation
  - incorrect-authorization
  - cve-2026-33519
  - webserver
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-33519
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33519
  - https://www.esri.com/arcgis-blog/products/trust-arcgis/administration/april2026_security_bulletin
rules:
  - title: Detect Suspicious ArcGIS Developer API Usage
    description: Detects potential exploitation attempts of CVE-2026-33519 by monitoring for unusual activity on ArcGIS Portal developer API endpoints.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Role Modification in ArcGIS Portal
    description: Detects potential privilege escalation by monitoring for unauthorized attempts to modify user roles within ArcGIS Portal.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-33519 is a critical incorrect authorization vulnerability affecting Esri Portal for ArcGIS versions 11.4, 11.5, and 12.0. This flaw exists across Windows, Linux, and Kubernetes deployments and stems from the application's failure to properly validate permissions assigned to developer credentials. This oversight allows attackers with malicious intent to potentially bypass intended authorization controls and escalate privileges within the ArcGIS portal. Given the widespread use of ArcGIS in critical infrastructure and mapping applications, this vulnerability poses a significant risk to organizations relying on these systems. Successful exploitation could lead to unauthorized access to sensitive data, modification of system configurations, or disruption of critical services.

## Attack Chain

1. An attacker gains initial access to the Esri Portal for ArcGIS application, potentially through compromised developer credentials or exploiting other vulnerabilities.
2. The attacker leverages developer APIs or interfaces within ArcGIS Portal.
3. The attacker attempts to perform actions that require elevated privileges but lack proper authorization checks due to the vulnerability (CVE-2026-33519).
4. The system incorrectly grants the attacker access to restricted functions or data due to the insufficient permission validation.
5. The attacker escalates privileges by exploiting the unauthorized access to modify user roles or system configurations.
6. The attacker leverages elevated privileges to access sensitive data stored within the ArcGIS Portal, such as maps, geospatial data, or user information.
7. The attacker may further compromise the system by installing malicious extensions or modifying core system files.
8. The attacker achieves complete control over the ArcGIS Portal, potentially leading to data breaches, service disruption, or further lateral movement within the network.

## Impact

Successful exploitation of CVE-2026-33519 can lead to significant damage, including unauthorized access to sensitive geospatial data, modification of critical system configurations, and potential disruption of services reliant on ArcGIS Portal. Given the wide use of ArcGIS in government, utilities, and transportation sectors, a successful attack could impact essential services. The lack of proper authorization checks on developer credentials can expose organizations to data breaches, financial losses, and reputational damage. This vulnerability affects all deployments of Esri Portal for ArcGIS 11.4, 11.5, and 12.0 on Windows, Linux, and Kubernetes, potentially impacting a large number of organizations globally.

## Recommendation

*   Apply the security patch released by Esri to address CVE-2026-33519 immediately after thorough testing in a non-production environment.
*   Review and enforce strict permission controls for all developer credentials used within Esri Portal for ArcGIS to minimize the attack surface.
*   Implement the Sigma rule `Detect Suspicious ArcGIS Developer API Usage` to identify potential exploitation attempts targeting CVE-2026-33519.
*   Monitor web server logs for unusual activity related to developer API endpoints in ArcGIS Portal, looking for unauthorized access attempts.
*   Enable detailed logging for ArcGIS Portal's authorization and authentication mechanisms to improve visibility into potential privilege escalation attempts.
