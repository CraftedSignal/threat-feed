---
title: Unauthenticated Administrative Access in Portal for ArcGIS
slug: 2026-10-portal-arcgis-cve
description: CVE-2026-69227 is a critical vulnerability in Portal for ArcGIS that allows unauthenticated access to administrative /portaladmin/local API endpoints, potentially permitting unauthorized administrative actions.
date: "2026-10-13T18:36:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:esri:portal_for_arcgis:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - arcgis
vendors:
  - Esri
products:
  - Portal for ArcGIS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A flaw in Portal for ArcGIS allows unauthenticated access to certain /portaladmin/local API endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-69227
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69227
rules:
  - title: Detect Unauthenticated Access Attempts to ArcGIS Administration API
    description: Detects potentially unauthorized access to the Portal for ArcGIS administrative API endpoint /portaladmin/local, which is associated with CVE-2026-69227.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided detection rule for monitoring /portaladmin/local access.
      owner: Detection Engineering
      due: 48h
      evidence: CVE-2026-69227 vulnerability details.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /portaladmin/local using WAF or firewall rules.
      owner: IT Operations
      addresses: CVE-2026-69227
      evidence: NVD vulnerability description.
---

CVE-2026-69227 is a critical vulnerability (CVSS v3.1 score 9.8) affecting Esri Portal for ArcGIS. The flaw resides within the portal's administrative API, specifically targeting the /portaladmin/local endpoint. Under specific, documented configurations, the vulnerability allows unauthenticated attackers to bypass authentication controls and interact with functionality that is intended to be restricted to administrative users. This exposure allows a remote attacker to potentially manipulate portal settings, manage user accounts, or perform other unauthorized administrative actions without providing valid credentials. Given the core role of Portal for ArcGIS in managing geospatial data and services, this represents a significant security risk for organizations relying on the platform. Defenders should treat this as a high-priority update item, as the reach of the affected API covers critical administrative operations.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to sensitive administrative functions within the ArcGIS environment. The potential damage includes the compromise of portal integrity, unauthorized changes to service configurations, and potential exfiltration or manipulation of geospatial data managed through the portal. While no specific victim counts are currently available, the prevalence of Portal for ArcGIS in enterprise and government geospatial infrastructure makes this a high-value target for threat actors.

## Recommendation

Prioritized actions for detection engineering teams include monitoring for unauthorized access attempts to the management interface.

* Review web server and application logs for GET or POST requests directed at /portaladmin/local from unauthorized or external IP addresses.
* Patch all instances of Portal for ArcGIS to the vendor-provided fixed version immediately upon release by Esri.
* Restrict network access to the /portaladmin/local endpoint at the edge firewall or web application firewall (WAF) to known administrative IP ranges until patching is complete.
