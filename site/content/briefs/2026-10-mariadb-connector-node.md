---
title: Multiple Vulnerabilities in MariaDB Connector/Node.js
slug: 2026-10-mariadb-connector-node
description: MariaDB Connector/Node.js is vulnerable to multiple security flaws, including SQL injection, information disclosure, data manipulation, and denial-of-service, allowing remote unauthenticated attackers to compromise data.
date: "2026-10-09T12:54:25Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:oracle:e-business_suite:*:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:vmware_vsphere:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:windows:*:*
  - cpe:2.3:a:netapp:oncommand_insight:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:oncommand_workflow_automation:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:snapcenter:-:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - database
  - nodejs
vendors:
  - MariaDB
products:
  - Connector/Node.js
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen in MariaDB Connector/Node.js ausnutzen, um einen Denial of Service Angriff durchzuführen
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen in MariaDB Connector/Node.js ausnutzen
    confidence_band: high
cves:
  - id: CVE-2024-21088
    cvss: 7.5
    epss: 0.0052
  - id: CVE-2024-21096
    cvss: 4.9
    epss: 0.00424
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3838
  - https://nvd.nist.gov/vuln/detail/CVE-2024-21088
  - https://nvd.nist.gov/vuln/detail/CVE-2024-21096
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all Node.js applications utilizing MariaDB Connector/Node.js
      owner: Application Security
      due: 48h
      evidence: General vulnerability mitigation requirement
  mitigation_plan:
    - priority: immediate
      action: Upgrade MariaDB Connector/Node.js to patched version
      owner: IT Operations
      addresses: CVE-2024-21088, CVE-2024-21096
      evidence: Vendor advisory
---

MariaDB Connector/Node.js contains multiple security vulnerabilities (CVE-2024-21088, CVE-2024-21096) that expose applications to significant risks. An unauthenticated remote attacker can exploit these flaws to perform SQL injection attacks, leading to the unauthorized disclosure or manipulation of database content. Furthermore, the vulnerabilities enable attackers to trigger a Denial of Service (DoS) condition, impacting the availability of the affected service. These issues affect the connector used for database communication in Node.js environments and represent a critical risk for backend systems relying on this library to interact with MariaDB databases. Defenders should identify all instances of the affected connector within their application stack and ensure updates are applied to remediate the underlying flaws.

## Impact

Successful exploitation allows remote attackers to bypass security controls, resulting in complete database compromise including unauthorized data access, modification of records, or service disruption. This affects any application utilizing the vulnerable MariaDB Connector/Node.js library to handle database queries, potentially impacting confidentiality, integrity, and availability of backend data.

## Recommendation

Prioritized actions for detection and remediation teams:
- Inventory all Node.js applications to identify dependencies on MariaDB Connector/Node.js.
- Review database query logs for patterns indicative of SQL injection attempts, such as unusual character sequences in query parameters.
- Implement application-level input validation and parameterized queries to mitigate the risk of SQL injection until patches are deployed.
- Upgrade MariaDB Connector/Node.js to the latest version as recommended by the vendor to remediate CVE-2024-21088 and CVE-2024-21096.
