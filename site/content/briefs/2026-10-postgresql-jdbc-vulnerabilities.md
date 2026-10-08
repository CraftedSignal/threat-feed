---
title: Multiple Vulnerabilities in PostgreSQL JDBC Driver
slug: 2026-10-postgresql-jdbc-vulnerabilities
description: The PostgreSQL JDBC Driver is susceptible to multiple vulnerabilities, including CVE-2022-21724 and CVE-2022-31197, that allow remote attackers to manipulate data and disclose sensitive information.
date: "2026-10-08T19:18:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:postgresql:postgresql_jdbc_driver:*:*:*:*:*:*:*:*
  - cpe:2.3:a:postgresql:postgresql_jdbc_driver:42.3.2:rc1:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*
  - cpe:2.3:a:quarkus:quarkus:*:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
  - cpe:2.3:a:postgresql:postgresql_jdbc_driver:42.4.0:*:*:*:*:*:*:*
  - cpe:2.3:a:postgresql:postgresql_jdbc_driver:42.4.1:rc1:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:36:*:*:*:*:*:*:*
vendors:
  - PostgreSQL
products:
  - PostgreSQL JDBC Driver
cves:
  - id: CVE-2022-21724
    cvss: 7
    epss: 0.03094
  - id: CVE-2022-31197
    cvss: 7.1
    epss: 0.02225
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3807
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all applications using the PostgreSQL JDBC Driver and confirm patch status.
      owner: IT Operations
      due: 72h
      evidence: Source document identifies vulnerabilities in the driver.
  mitigation_plan:
    - priority: immediate
      action: Update PostgreSQL JDBC Driver to the latest version.
      owner: Application Security
      addresses: CVE-2022-21724, CVE-2022-31197
      evidence: Source identifies these CVEs as affecting the driver.
---

The PostgreSQL JDBC Driver is affected by multiple security vulnerabilities, specifically tracked under CVE-2022-21724 and CVE-2022-31197. These vulnerabilities arise from improper handling of connection properties and authentication mechanisms within the driver. An attacker capable of influencing the connection parameters or environment where the driver operates could potentially exploit these flaws to bypass intended security controls. Successful exploitation allows for unauthorized data manipulation and the disclosure of sensitive information within applications that rely on the affected PostgreSQL JDBC Driver for database connectivity. Defenders should prioritize updating the driver to a patched version across all integrated environments to mitigate the risk of unauthorized database interactions.

## Impact

Successful exploitation of these vulnerabilities can lead to the loss of data integrity via unauthorized modification and the compromise of confidentiality through the exposure of sensitive database content. Organizations utilizing Java-based applications that interface with PostgreSQL databases are primarily at risk, as the JDBC driver is a core dependency for these connections. The potential impact ranges from localized data leaks to broader application-level compromises depending on the application's implementation of database authentication and authorization.

## Recommendation

Prioritize auditing the software inventory to identify all applications and services currently utilizing the PostgreSQL JDBC Driver. Evaluate these instances against the patched version requirements provided by the PostgreSQL project and ensure all affected instances are updated to versions that contain security fixes for CVE-2022-21724 and CVE-2022-31197. If immediate patching is not possible, review application connection configurations to identify and restrict any untrusted input that could influence JDBC connection properties or connection strings.
