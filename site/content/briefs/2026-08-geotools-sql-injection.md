---
title: Unauthenticated SQL Injection in GeoTools PostGIS DataStore
slug: 2026-08-geotools-sql-injection
description: A critical unauthenticated SQL injection vulnerability (CVE-2026-76904) in the GeoTools library allows remote attackers to execute arbitrary SQL via the jsonArrayContains filter function.
date: "2026-08-22T01:16:54Z"
lastmod: "2026-08-26T12:03:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=749B42C3-18F4-5F09-AA97-A5CBE50DFF57&utm_source=rss&utm_medium=rss
tags:
  - sql-injection
  - vulnerability
  - application-security
vendors:
  - OSGeo
products:
  - GeoTools
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An SQL Injection Vulnerability has been found when executing OGC Filters with PostGIS DataStore implementation
    confidence_band: high
cves:
  - id: CVE-2026-76904
    cvss: 9.8
    epss: 0.00524
references:
  - https://github.com/advisories/GHSA-mqjf-5f49-2fjh
  - https://osgeo-org.atlassian.net/browse/GEOT-7958
  - https://osgeo-org.atlassian.net/browse/GEOT-7959
  - https://osgeo-org.atlassian.net/browse/GEOT-7589
  - https://github.com/geotools/geotools/pull/5829
  - https://sploitus.com/exploit?id=749B42C3-18F4-5F09-AA97-A5CBE50DFF57&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade gt-jdbc-postgis to versions 35.1, 33.5, or 34.4
      owner: IT Operations
      due: 24h
      evidence: Vendor patch recommendation for CVE-2026-76904
  mitigation_plan:
    - priority: immediate
      action: Limit database service account permissions for GeoTools application
      owner: Database Administration
      addresses: CVE-2026-76904
      evidence: Recommended mitigation by OSGeo
updates:
  - at: "2026-08-26T12:03:27Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=749B42C3-18F4-5F09-AA97-A5CBE50DFF57&utm_source=rss&utm_medium=rss
---

GeoTools, a popular Java library for geospatial data, contains a critical SQL injection vulnerability (CVE-2026-76904) within its PostGIS DataStore implementation. The flaw resides in the jsonArrayContains filter function, which fails to properly sanitize the input value parameter when generating SQL queries for databases running PostGIS 12 or later. By providing malicious input to this function, an unauthenticated attacker can inject arbitrary SQL commands into the backend database. This vulnerability affects multiple versions of the gt-jdbc-postgis package, specifically versions 35.0, 34.0 through 34.4, and 30.5 through 33.5. Impacted organizations are advised to upgrade to the patched versions (35.1, 33.5, or 34.4) immediately. If upgrading is not immediately feasible, the attack surface can be limited by ensuring the database connection pool used by the GeoTools application is configured with the principle of least privilege, specifically restricting write and administrative permissions.

## Impact

Successful exploitation allows remote, unauthenticated attackers to execute arbitrary SQL expressions against the underlying database. This potentially results in complete data exfiltration, unauthorized modification of geospatial datasets, and database-level compromise. The vulnerability is highly severe due to its unauthenticated nature and the direct access to database operations.

## Recommendation

- Upgrade the gt-jdbc-postgis library to versions 35.1, 33.5, or 34.4 immediately to resolve CVE-2026-76904.
- Review database connection pool configurations and restrict the service account privileges assigned to GeoTools to the minimum required subset of data (SELECT only where possible).
- Enable detailed logging for database queries in the application layer to monitor for anomalous SQL syntax or unexpected execution patterns that may indicate exploitation attempts.
