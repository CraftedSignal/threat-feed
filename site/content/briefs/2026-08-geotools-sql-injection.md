---
title: Critical SQL Injection Vulnerability in GeoTools Library
slug: 2026-08-geotools-sql-injection
description: A critical SQL injection vulnerability in the GeoTools Java library allows unauthenticated remote attackers to execute arbitrary database commands, leading to potential data exfiltration or full server compromise.
date: "2026-08-18T13:58:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - java
  - geotools
  - critical-patch
products:
  - GeoTools
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: De kwetsbaarheid maakt het mogelijk dat een aanvaller via SQL-injectie schadelijke code kan uitvoeren in de database die door GeoTools wordt gebruikt.
    confidence_band: high
references:
  - https://www.ncsc.nl/alerts/kritieke-sql-injectie-in-geotools-open-source-java-bibliotheek-update-onmiddellijk
  - https://advisories.ncsc.nl/2026/ncsc-2026-0304.html
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all applications utilizing GeoTools library.
      owner: IT Operations
      due: 24h
      evidence: Source states GeoTools is a library used in systems that manage geographic information.
  mitigation_plan:
    - priority: immediate
      action: Upgrade GeoTools to 33.6, 34.5, or 35.1.
      owner: IT Operations
      addresses: GeoTools SQL injection vulnerability
      evidence: NCSC advises to install the updates provided by the supplier.
---

The open-source GeoTools Java library, widely used for geospatial data processing and visualization, contains a critical SQL injection vulnerability (CVSS 9.8). This vulnerability allows unauthenticated attackers to supply malicious input that is executed as part of database queries performed by the library. Depending on the database service permissions, this could result in unauthorized data access, modification, or deletion. In scenarios where the database service runs with elevated privileges, it may lead to full system compromise. The vulnerability is currently being actively scanned by malicious actors, though large-scale exploitation has not yet been reported. Patches are available in versions 33.6, 34.5, and 35.1. Defenders should prioritize auditing systems that utilize GeoTools and apply the recommended version updates immediately.

## Impact

Successful exploitation allows attackers to gain unauthorized access to sensitive geospatial data. The potential for server-wide compromise poses significant risks, including data breaches, loss of data integrity, and prolonged service disruption. The threat is elevated due to active scanning activity in the wild.

## Recommendation

* Update all instances of GeoTools to versions 33.6, 34.5, or 35.1 immediately to remediate the vulnerability.
* Audit application inventory to identify systems running vulnerable versions of GeoTools.
* Review database service permissions; ensure the database account used by the GeoTools-dependent application follows the principle of least privilege to mitigate the impact of potential command execution.
* Monitor application logs for abnormal database query patterns, such as unexpected SQL syntax characters (e.g., ;, --, OR 1=1) originating from external user inputs.
