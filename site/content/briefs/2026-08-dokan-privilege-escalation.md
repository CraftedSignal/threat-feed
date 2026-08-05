---
title: 'CVE-2026-8761: Privilege Escalation in Dokan WordPress Plugin'
slug: 2026-08-dokan-privilege-escalation
description: An improper authorization flaw in the Dokan plugin for WordPress allows authenticated attackers with vendor-level access to escalate privileges to administrator via manipulation of the REST API.
date: "2026-08-05T08:06:36Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - weDevs
  - WooCommerce
products:
  - Dokan
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers with Vendor/Seller-level access and above to read, modify, or delete any WordPress user.
    confidence_band: high
cves:
  - id: CVE-2026-8761
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8761
rules:
  - title: Detect CVE-2026-8761 Exploitation Attempt
    description: Detects unauthorized attempts to modify user data via the Dokan REST API namespace associated with CVE-2026-8761.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Dokan plugin to current version.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows full site takeover via password reset.
  hunt_leads:
    - lead: Search web logs for PUT/DELETE requests to /wp-json/dokan/v1/customers/.
      technique_id: T1068
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Endpoint documentation provided in the vulnerability details.
  mitigation_plan:
    - priority: immediate
      action: Update Dokan plugin.
      owner: IT Operations
      addresses: CVE-2026-8761
      evidence: Plugin version 5.0.1 and earlier are confirmed vulnerable.
---

The Dokan plugin for WordPress (versions 5.0.1 and earlier) is vulnerable to a severe privilege escalation vulnerability tracked as CVE-2026-8761. The issue originates in the `CustomersController` REST controller located at `includes/REST/CustomersController.php`. The plugin registers custom REST routes under the `/dokan/v1/customers/` namespace by re-implementing WooCommerce customer CRUD functionality. 

Critically, the implementation fails to perform an authorization check on the target user object, instead performing a flawed check on the requesting user's role. Consequently, any user with 'Vendor' or 'Seller' capabilities can interact with the API to read, update, or delete any arbitrary user within the WordPress database. An attacker can specifically target an administrator's record and modify the `password` parameter, resulting in a complete site takeover. This vulnerability poses an extreme risk for multi-vendor WordPress environments utilizing the Dokan plugin.

## Impact

Successful exploitation results in full administrative control over the affected WordPress installation. Given the prevalence of Dokan in e-commerce deployments, this vulnerability facilitates unauthorized access to sensitive customer data, order history, and platform settings. If exploited, an attacker can modify administrative account credentials, inject malicious code, or exfiltrate databases associated with the site.

## Recommendation

* Immediately update the Dokan plugin to a version patched against CVE-2026-8761.
* Audit WordPress user logs for unexpected modifications to administrative accounts.
* Monitor REST API traffic for unauthorized `PUT` or `DELETE` requests targeting the `/wp-json/dokan/v1/customers/` endpoint.
* Restrict access to administrative dashboard functions and API endpoints to trusted IP ranges where feasible.
