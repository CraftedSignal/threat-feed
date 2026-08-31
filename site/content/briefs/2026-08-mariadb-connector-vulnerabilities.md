---
title: Multiple Vulnerabilities in MariaDB Connectors
slug: 2026-08-mariadb-connector-vulnerabilities
description: Multiple vulnerabilities in MariaDB Connector libraries enable remote, unauthenticated attackers to perform SQL injection, bypass security controls, and manipulate sensitive database content.
date: "2026-08-31T11:57:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:pixelite:events_manager:*:*:*:*:*:wordpress:*:*
  - cpe:2.3:a:10web:form_maker:*:*:*:*:*:wordpress:*:*
tags:
  - vulnerability
  - database
  - injection
vendors:
  - MariaDB
products:
  - MariaDB Connectors
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote, unauthenticated attacker can exploit multiple vulnerabilities in MariaDB Connectors to conduct SQL injection.
    confidence_band: high
cves:
  - id: CVE-2024-2110
    cvss: 4.3
    epss: 0.00215
  - id: CVE-2024-2111
    cvss: 6.4
    epss: 0.0034
  - id: CVE-2024-2112
    cvss: 5.9
    epss: 0.00699
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3089
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2106
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2107
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2108
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2109
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2110
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2111
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2112
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory applications using MariaDB Connectors and plan patching for identified vulnerable versions.
      owner: IT Operations
      due: 72h
      evidence: Advisory details the need for patching multiple vulnerabilities.
  mitigation_plan:
    - priority: immediate
      action: Upgrade MariaDB Connectors to the latest non-vulnerable versions.
      owner: IT Operations
      addresses: CVE-2024-2106, CVE-2024-2107, CVE-2024-2108, CVE-2024-2109, CVE-2024-2110, CVE-2024-2111, CVE-2024-2112
      evidence: Source identifies vulnerabilities in MariaDB Connectors.
---

The German Federal Office for Information Security (BSI) has released an advisory regarding multiple vulnerabilities affecting MariaDB Connector libraries. These flaws, identified as CVE-2024-2106, CVE-2024-2107, CVE-2024-2108, CVE-2024-2109, CVE-2024-2110, CVE-2024-2111, and CVE-2024-2112, collectively pose a significant risk to application integrity. An unauthenticated remote attacker can exploit these issues to perform SQL injection attacks, bypass security measures, and gain unauthorized access to data. These connector libraries are often embedded within third-party applications, meaning the scope of the impact extends to any software utilizing these specific MariaDB drivers to interface with database systems. Defenders should identify instances of MariaDB connectors within their environments and ensure they are patched to the latest versions released by the vendor.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to execute arbitrary SQL commands against backend databases. This results in the potential for unauthorized data exfiltration, modification of database records, and in some configurations, complete compromise of the database integrity. Organizations relying on applications that utilize vulnerable MariaDB connectors are at risk of data breaches and service disruption.

## Recommendation

* Identify all internal and vendor-supplied applications that integrate MariaDB Connector libraries.
* Update all instances of vulnerable MariaDB connectors to the latest patched versions provided by MariaDB.
* Monitor application and database logs for anomalous SQL queries originating from web-facing services, particularly those indicative of SQL injection patterns (e.g., unexpected UNION, OR, or comment characters).
