---
title: SQL Injection in Shandong Hoteam PDM Product Data Management System
slug: 2026-08-shandong-hoteam-sqli
description: Shandong Hoteam PDM Product Data Management System versions 8.3.10 and earlier contain a SQL injection vulnerability in the GetStoredClassByFilter function that allows remote, unauthenticated attackers to execute arbitrary SQL commands.
date: "2026-08-05T02:04:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - injection
  - sql-injection
  - cve-2026-18854
vendors:
  - Shandong Hoteam
products:
  - PDM Product Data Management System
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
cves:
  - id: CVE-2026-18854
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18854
  - https://vuldb.com/vuln/385866
rules:
  - title: Detect CVE-2026-18854 Exploitation - SQL Injection in PDM Product Data Management System
    description: Detects attempts to exploit CVE-2026-18854 by monitoring HTTP requests to the vulnerable GetStoredClassByFilter function containing common SQL injection syntax in the FilterString parameter.
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
    - action: Deploy WAF/Detection rule for CVE-2026-18854.
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms remote exploitation is possible and public exploit material exists.
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the vulnerable PDM service.
      owner: IT Operations
      addresses: CVE-2026-18854
      evidence: Source identifies this as a remote, unauthenticated exploitation vector.
---

A critical SQL injection vulnerability (CVE-2026-18854) has been identified in the Shandong Hoteam PDM Product Data Management System in versions up to 8.3.10. The vulnerability resides within the GetStoredClassByFilter function in the /Base/BaseService.asmx/DataService file. By sending a specially crafted 'FilterString' argument to this endpoint, an unauthenticated, remote attacker can manipulate backend database queries. This flaw poses a significant risk to organizational data integrity and confidentiality, as it enables unauthorized access to the underlying database management system. Publicly available exploit material has been disclosed, and as the vendor has not provided a resolution, administrators are urged to restrict network access to the affected web service components immediately.

## Attack Chain

1. The attacker performs reconnaissance to identify internet-facing PDM web services utilizing the vulnerable /Base/BaseService.asmx endpoint.
2. The attacker identifies the target endpoint, /Base/BaseService.asmx/DataService, responsible for handling class filtering requests.
3. The attacker crafts a malicious HTTP GET or POST request targeting the 'FilterString' parameter within the GetStoredClassByFilter function.
4. The input is passed directly to the backend database engine without proper sanitization or parameterization.
5. The injected SQL command is executed by the database, allowing the attacker to bypass access controls, exfiltrate data, or modify database entries.
6. If the database service account has excessive privileges, the attacker may further leverage the injection to interact with the underlying host OS.
7. The final objective is typically data exfiltration or the establishment of persistent unauthorized database access.

## Impact

Successful exploitation allows an unauthenticated attacker to execute arbitrary SQL commands against the backend database. This can lead to the unauthorized disclosure of sensitive product data, modification of existing records, or complete compromise of the database integrity. Given that the product manages proprietary engineering and product design data, the impact of a breach could include the loss of sensitive intellectual property and disruption of manufacturing processes.

## Recommendation

* Deploy the provided webserver-level detection rule to identify and block incoming requests containing suspected SQL injection patterns directed at the /Base/BaseService.asmx/DataService endpoint.
* Restrict access to the PDM web management interface to internal, trusted network segments via firewall controls to mitigate the remote exploitation vector.
* Audit database access logs for unusual queries or bulk data retrieval patterns originating from the application service account to detect potential exploitation activity.
* If the software cannot be patched, consider placing a Web Application Firewall (WAF) in front of the application to inspect and filter the 'FilterString' parameter for SQL injection payloads.
