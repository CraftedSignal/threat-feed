---
title: SQL Injection in Smart Manager for WooCommerce
slug: 2026-10-smart-manager-sql-injection
description: An authenticated SQL injection vulnerability in the Smart Manager plugin for WordPress allows subscriber-level users to perform database exfiltration through the access_privileges parameter.
date: "2026-10-03T08:54:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:storeapps:smart_manager_for_woocommerce:*:*:*:*:*:wordpress:*:*
vendors:
  - StoreApps
products:
  - Smart Manager for WooCommerce (<= 8.97.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for authenticated attackers, with subscriber-level access and above, to append additional SQL queries into already existing queries.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for authenticated attackers... to append additional SQL queries into already existing queries that can be used to extract sensitive information.
    confidence_band: high
cves:
  - id: CVE-2026-18443
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18443
rules:
  - title: Detects CVE-2026-18443 Exploitation - SQL Injection via access_privileges
    description: Detects exploitation of CVE-2026-18443 by monitoring for SQL injection patterns in HTTP requests targeting the Smart Manager access_privileges handler
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
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Smart Manager for WooCommerce to a version higher than 8.97.0
      owner: IT Operations
      due: 48h
      evidence: Plugin version <= 8.97.0 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Review and restrict role-based Access Privileges in Smart Manager settings
      owner: IT Operations
      addresses: CVE-2026-18443
      evidence: Exploit requires specific administrator misconfiguration of deny-lists
---

The Smart Manager for WooCommerce plugin (versions 8.97.0 and below) contains a critical SQL injection vulnerability identified as CVE-2026-18443. The flaw exists due to inadequate input sanitization and lack of parameterized queries within the 'access_privileges' parameter handling logic. Attackers with at least subscriber-level access can manipulate database queries to exfiltrate sensitive information. This exploitation vector is specifically viable on installations where an administrator has configured a role-based deny-list for Access Privileges but failed to explicitly exclude the internal 'access-privilege' module. Because of this oversight, the authorization filter erroneously permits lower-privileged users to invoke the vulnerable handler, enabling unauthorized database interaction.

## Impact

Successful exploitation allows authenticated attackers with subscriber-level access to execute arbitrary SQL commands against the underlying WordPress database. This can lead to the unauthorized extraction of sensitive business data, customer information, or administrative credentials stored within the WooCommerce environment. The vulnerability impacts all WordPress installations running the affected plugin versions where specific, non-restrictive access configurations are present.

## Recommendation

- Upgrade the 'Smart Manager - Advanced WooCommerce Bulk Edit & Inventory Management' plugin to the latest version (above 8.97.0) immediately.
- Review role-based Access Privilege configurations in the Smart Manager dashboard to ensure the 'access-privilege' module is explicitly restricted for all non-administrative user roles.
- Audit database access logs and monitor for anomalous SQL syntax errors or query patterns originating from subscriber-level user sessions.
