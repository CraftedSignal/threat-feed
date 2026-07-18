---
title: SurrealDB Default Permissions Vulnerability
slug: 2026-07-surrealdb-default-permissions
description: SurrealDB versions prior to 1.0.1 are vulnerable due to default table permissions being set to FULL instead of NONE, allowing attackers with existing database access or unauthenticated users on publicly exposed instances to perform unrestricted SELECT, CREATE, UPDATE, and DELETE operations on tables that lack explicit permission settings, leading to unauthorized data access, modification, or deletion.
date: "2026-07-18T14:19:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - misconfiguration
  - database
  - vulnerability
  - data-exfiltration
vendors:
  - SurrealDB
products:
  - SurrealDB (before 1.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers with database access or unauthenticated users on publicly exposed instances can perform unrestricted operations
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1565
    technique_name: Stolen Data
    evidence: allowing SELECT, CREATE, UPDATE, and DELETE operations on tables without explicit permissions... leading to unauthorized data access
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: allowing SELECT, CREATE, UPDATE, and DELETE operations on tables without explicit permissions... leading to unauthorized data... deletion.
    confidence_band: med
cves:
  - id: CVE-2023-54366
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-54366
---

CVE-2023-54366 details a critical vulnerability in SurrealDB versions prior to 1.0.1 where the default table permissions are configured to FULL instead of NONE. This misconfiguration allows unauthenticated users or those with existing database access on publicly exposed instances to bypass intended access controls. Attackers can perform a wide range of operations including SELECT, CREATE, UPDATE, and DELETE on any table within their authorization scope that does not have explicit permission settings. This flaw presents a significant risk to data confidentiality, integrity, and availability, potentially leading to unauthorized data exposure, manipulation, or complete deletion. Organizations using affected SurrealDB instances are strongly advised to patch immediately to prevent exploitation.

## Attack Chain

1. Attacker identifies a publicly exposed SurrealDB instance lacking proper network access controls or gains initial unauthorized access to a SurrealDB database.
2. Attacker initiates a connection to the vulnerable SurrealDB instance.
3. Attacker queries the database for existing tables and their schema.
4. The vulnerability (CVE-2023-54366) allows default permissions to be "FULL" for tables lacking explicit "NONE" settings.
5. Attacker exploits these default permissions to perform unauthorized `SELECT` operations on sensitive tables, leading to data exfiltration.
6. Attacker further utilizes `CREATE`, `UPDATE`, or `DELETE` operations on tables to manipulate or destroy data within the database.
7. The attack culminates in unauthorized data access, modification, or deletion, compromising the integrity and confidentiality of the data.

## Impact

Successful exploitation of CVE-2023-54366 can lead to severe consequences, primarily affecting data confidentiality, integrity, and availability. Attackers can read sensitive information from any unprotected table, resulting in data breaches and regulatory non-compliance. They can also create, modify, or delete existing data, leading to data corruption, financial fraud, or service disruption. The impact is especially critical for publicly exposed instances, where unauthenticated attackers could perform these operations, affecting potentially all data stored in misconfigured tables. The extent of damage depends on the sensitivity of the data and the attacker's objectives.

## Recommendation

* Patch SurrealDB to version 1.0.1 or later to address CVE-2023-54366 immediately.
* Review all SurrealDB table definitions and explicitly set permissions for sensitive tables to `NONE` for unauthenticated or untrusted users, or as required by your security policy.
* Restrict network access to SurrealDB instances, ensuring they are not publicly exposed unless absolutely necessary, and only accessible from trusted IP ranges.
