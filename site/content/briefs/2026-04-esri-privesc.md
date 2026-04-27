---
title: Esri Portal for ArcGIS Incorrect Authorization Vulnerability (CVE-2026-33519)
slug: 2026-04-esri-privesc
description: CVE-2026-33519 is a critical vulnerability in Esri Portal for ArcGIS 11.4, 11.5, and 12.0, where incorrect authorization checks on developer credentials can lead to unauthorized privilege escalation on Windows, Linux, and Kubernetes deployments.
date: "2026-04-21T21:16:29Z"
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

CVE-2026-33519 is a critical incorrect authorization vulnerability affecting Esri Portal for ArcGIS versions 11.4, 11.5, and 12.0. This flaw exists across Windows, Linux, and Kubernetes deployments and stems from the application's failure to properly validate permissions assigned to developer credentials. This oversight allows attackers with malicious intent to potentially bypass intended authorization controls and escalate privileges within the ArcGIS portal. Given the widespread use of ArcGIS…
