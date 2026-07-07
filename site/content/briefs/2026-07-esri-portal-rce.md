---
title: Critical Unauthenticated API Access in Esri Portal for ArcGIS (CVE-2026-13019)
slug: 2026-07-esri-portal-rce
description: A critical missing authentication vulnerability (CVE-2026-13019) in Esri Portal for ArcGIS versions 12.1 and earlier allows a remote, unauthenticated attacker to access unprotected critical APIs, impacting deployments on Windows, Linux, and Kubernetes environments.
date: "2026-07-07T17:17:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - esri
  - arcgis
  - unauthenticated-access
  - api-security
  - rce
vendors:
  - Esri
products:
  - Portal for ArcGIS 12.1 and earlier
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: missing authentication for critical function vulnerability allows a remote, unauthenticated attacker to access an unprotected API.
    confidence_band: high
cves:
  - id: CVE-2026-13019
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13019
---

A critical missing authentication vulnerability, tracked as CVE-2026-13019, has been identified in Esri Portal for ArcGIS versions 12.1 and earlier. This flaw allows a remote, unauthenticated attacker to bypass authentication mechanisms and directly access critical API functions. With a CVSS v3.1 base score of 9.8, this vulnerability poses an extreme risk, enabling attackers to potentially manipulate or extract sensitive Geographic Information System (GIS) data, compromise system integrity, or perform unauthorized administrative operations. The vulnerability affects deployments across various platforms, including Windows, Linux, and Kubernetes environments, making a wide range of organizations using Esri's GIS solutions susceptible to compromise. Immediate patching is imperative to mitigate the risk of unauthorized access and potential data breaches.

## Attack Chain

1.  Attacker identifies a public-facing Esri Portal for ArcGIS instance running version 12.1 or earlier.
2.  Attacker researches or discovers the specific critical API endpoints vulnerable to authentication bypass.
3.  Attacker crafts an HTTP request targeting a known critical API endpoint on the vulnerable Esri Portal for ArcGIS system.
4.  The crafted request is sent to the Esri Portal for ArcGIS web server without including valid authentication credentials.
5.  Due to the missing authentication vulnerability (CVE-2026-13019), the Esri Portal for ArcGIS processes the unauthenticated request as if it were legitimate.
6.  The attacker successfully gains unauthorized access to the unprotected critical API, enabling them to invoke sensitive functions or retrieve privileged information.

## Impact

Successful exploitation of CVE-2026-13019 grants remote, unauthenticated attackers full access to critical API functions within Esri Portal for ArcGIS. This can lead to a range of severe consequences, including unauthorized viewing, modification, or deletion of sensitive GIS data, system configuration changes, and potentially full compromise of the Esri Portal infrastructure. Organizations in sectors relying heavily on GIS data, such as government, utilities, and infrastructure, are particularly at risk. The broad platform applicability (Windows, Linux, Kubernetes) means a wide array of deployments are exposed, potentially leading to widespread data breaches or operational disruption.

## Recommendation

*   Patch CVE-2026-13019 on all Esri Portal for ArcGIS instances immediately by upgrading to a patched version (12.2 or later) or applying the vendor-provided security updates.
*   Review Esri Portal for ArcGIS web server access logs for anomalous unauthenticated access patterns to API endpoints that could indicate attempted or successful exploitation of CVE-2026-13019.
