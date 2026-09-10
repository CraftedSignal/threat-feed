---
title: Unauthenticated Category Addition in Rizwan17 inventory-management-system
slug: 2026-09-inventory-system-auth-bypass
description: An authentication bypass vulnerability in the AJAX backend of Rizwan17 inventory-management-system allows remote attackers to execute unauthorized category additions via the userid parameter.
date: "2026-09-09T23:02:46Z"
lastmod: "2026-09-10T01:02:56Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:rizwan17:inventory_management_system:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - auth-bypass
  - cve-2026-87922
vendors:
  - Rizwan17
products:
  - inventory-management-system (up to bfe78a330d01bb26b9daec5dc9ecd5c77900e03f)
  - inventory-management-system (<= bfe78a330d01bb26b9daec5dc9ecd5c77900e03f)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument userid results in missing authentication.
    confidence_band: high
cves:
  - id: CVE-2026-87922
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87922
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87921
rules:
  - title: Detect CVE-2026-87922 Exploitation - Unauthenticated Category Addition
    description: Detects exploitation attempts against the AJAX backend by monitoring for unauthorized access to the process.php endpoint with suspicious userid parameters.
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
    - action: Deploy WAF rules to intercept POST requests to /includes/process.php without valid session tokens
      owner: SOC
      due: 24h
      evidence: CVE-2026-87922 vulnerability report
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /includes/process.php via web server configuration
      owner: IT Operations
      addresses: CVE-2026-87922
      evidence: Public exploit availability
updates:
  - at: "2026-09-10T01:02:56Z"
    level: L2
    summary: added coverage for inventory-management-system (<= bfe78a330d01bb26b9daec5dc9ecd5c77900e03f)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-87921
---

A security vulnerability exists in the Rizwan17 inventory-management-system (commits up to bfe78a330d01bb26b9daec5dc9ecd5c77900e03f). The flaw is located within the DBOperation.addCategory function in the includes/process.php file, which handles AJAX backend requests. An attacker can manipulate the userid argument to bypass authentication checks, allowing for unauthorized modifications to the inventory categories. Because the project utilizes a rolling release model, no specific version numbers are assigned to the affected or patched code. Publicly available exploit code currently exists for this vulnerability, increasing the risk of active exploitation by remote threat actors. The project maintainers have been notified of the issue but have not yet provided a fix or response.

## Impact

Successful exploitation allows unauthenticated remote attackers to add unauthorized categories to the inventory system. This can be used to manipulate business logic, disrupt inventory tracking, or serve as a vector for further unauthorized database interactions within the application.

## Recommendation

* Monitor web server access logs for anomalous POST requests directed at /includes/process.php.
* Audit the application source code for the DBOperation.addCategory function and implement robust session validation checks for the userid parameter.
* Given the lack of a vendor-provided patch, consider placing the inventory-management-system behind a Web Application Firewall (WAF) or restricting access to the includes/ directory via IP-based access control lists (ACLs).
