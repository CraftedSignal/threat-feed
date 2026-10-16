---
title: SQL Injection in Vitepos POS for WooCommerce
slug: 2026-10-vitepos-sqli
description: The Vitepos plugin for WooCommerce is vulnerable to unauthenticated SQL injection via the 'src_by' parameter, potentially allowing unauthorized database information extraction.
date: "2026-10-16T10:26:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vitepos:vitepos:*:*:*:*:*:wordpress:*:*
tags:
  - web-application-vulnerability
  - sqli
  - wordpress
vendors:
  - WordPress
products:
  - Vitepos – Point of Sale (POS) for WooCommerce (<= 3.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Vitepos – Point of Sale (POS) for WooCommerce plugin for WordPress is vulnerable to generic SQL Injection via the 'src_by' parameter in all versions up to, and including, 3.5.1.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
    confidence_band: high
cves:
  - id: CVE-2026-92766
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92766
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Vitepos - Point of Sale (POS) for WooCommerce to a version greater than 3.5.1
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerability exists in versions up to 3.5.1
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /vitepos/v1/vendor/list via WAF or server configuration
      owner: Security Operations
      addresses: CVE-2026-92766
      evidence: Vulnerability is located in the REST route permission callback
---

The Vitepos - Point of Sale (POS) for WooCommerce plugin for WordPress (versions up to and including 3.5.1) contains a critical SQL injection vulnerability identified as CVE-2026-92766. The flaw exists within the /vitepos/v1/vendor/list REST API route, specifically via the 'src_by' parameter. The vulnerability arises from improper input sanitization and a failure to utilize prepared statements when constructing database queries. Furthermore, the permission callback for the vulnerable REST route is insufficient, requiring only a basic POS role assignment (such as vtpos-cashier) rather than standard WordPress administrative privileges. This combination allows unauthenticated or low-privileged users to manipulate back-end database queries, posing a significant risk of data exfiltration or unauthorized database access.

## Impact

Successful exploitation of this vulnerability permits an attacker to perform SQL injection attacks against the underlying WordPress database. This could result in the unauthorized disclosure of sensitive data, including customer information, credentials, or internal configuration data managed by the WooCommerce store. The impact is significant for organizations relying on this plugin for POS operations, as the affected endpoint is publicly reachable by default.

## Recommendation

1. Patch immediately by updating the Vitepos - Point of Sale (POS) for WooCommerce plugin to the latest version that addresses CVE-2026-92766.
2. Review access logs for web requests targeting the /vitepos/v1/vendor/list endpoint that include suspicious characters (e.g., ;, --, OR, UNION) in the 'src_by' parameter.
3. Restrict access to the WooCommerce REST API for non-administrative roles until the plugin has been patched.
