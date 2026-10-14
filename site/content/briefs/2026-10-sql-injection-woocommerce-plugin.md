---
title: SQL Injection in Abandoned Cart Pro for WooCommerce Plugin
slug: 2026-10-sql-injection-woocommerce-plugin
description: An unauthenticated SQL injection vulnerability in the Abandoned Cart Pro for WooCommerce plugin allows attackers to exfiltrate data or escalate privileges to administrator by modifying user metadata.
date: "2026-10-14T04:35:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:tychesoftwares:abandoned_cart_pro_for_woocommerce:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - Abandoned Cart Pro for WooCommerce (<= 10.8.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Abandoned Cart Pro for WooCommerce plugin for WordPress is vulnerable to SQL Injection via the guest cart persistent meta_value.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: it has been demonstrated to escalate an arbitrary account to administrator by writing a wp_capabilities row that shadows the legitimate one.
    confidence_band: high
cves:
  - id: CVE-2026-97668
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97668
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Abandoned Cart Pro for WooCommerce to latest patched version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-97668 vulnerability in <= 10.8.0
  mitigation_plan:
    - priority: immediate
      action: Patch plugin and review user accounts for unauthorized administrative privileges
      owner: Security Operations
      addresses: CVE-2026-97668
      evidence: Source documentation of RCE/Privilege escalation via wp_usermeta modification
---

The Abandoned Cart Pro for WooCommerce plugin for WordPress (versions up to and including 10.8.0) contains a critical SQL injection vulnerability in the update_guest_persistent_cart() function. The flaw stems from improper handling of the 'abandoned_cart_info' parameter, which is extracted from user-supplied checkout fields like SMS consent. While other parts of the SQL query use prepared statements, the affected UPDATE statement concatenates the meta_value directly after only basic stripslashes() sanitization. This allows unauthenticated attackers to append arbitrary SQL commands. The vulnerability is highly impactful as it targets the wp_usermeta table, enabling attackers to perform time-based blind SQL injection for data exfiltration or to manipulate user privileges by injecting malicious wp_capabilities rows, effectively elevating an arbitrary account to administrator status.

## Impact

Successful exploitation allows unauthenticated attackers to compromise the integrity and confidentiality of the WordPress database. Attackers can extract sensitive information or grant themselves administrative access, leading to full site takeover. The scope of impact includes any WordPress installation running the vulnerable Abandoned Cart Pro plugin version 10.8.0 or lower.

## Recommendation

- Upgrade the Abandoned Cart Pro for WooCommerce plugin to the latest version immediately to patch CVE-2026-97668.
- Review database audit logs for anomalous modifications to the wp_usermeta table, specifically looking for unexpected 'wp_capabilities' entries.
- Implement a Web Application Firewall (WAF) rule to block common SQL injection patterns in HTTP POST requests targeting WordPress checkout-related endpoints.
- Audit user accounts for unauthorized administrator roles granted during the incident timeframe.
