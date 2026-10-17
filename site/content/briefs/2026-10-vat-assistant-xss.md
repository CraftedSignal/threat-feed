---
title: Stored XSS in The EU VAT Assistant for WooCommerce Plugin
slug: 2026-10-vat-assistant-xss
description: An unauthenticated Stored Cross-Site Scripting vulnerability in The EU VAT Assistant for WooCommerce plugin (<= 2.1.30.260413) allows attackers to inject malicious scripts that execute in the administrator's context, potentially leading to account takeover.
date: "2026-10-17T04:48:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:wordpress:the_eu_vat_assistant_for_woocommerce:*:*:*:*:*:*:*:*
tags:
  - xss
  - wordpress
  - web-vulnerability
  - cve-2026-103899
vendors:
  - WordPress
products:
  - The EU VAT Assistant for WooCommerce (<= 2.1.30.260413)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The stored payload executes in the administrator's browser context ... enabling privilege escalation up to and including full site takeover.
    confidence_band: high
cves:
  - id: CVE-2026-103899
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103899
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade The EU VAT Assistant for WooCommerce plugin to the latest patched version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-103899 remediation
  hunt_leads:
    - lead: Search WordPress audit logs for user creation events triggered by unexpected sessions
      technique_id: T1059.007
      data_needed:
        - Web server logs
        - WordPress activity logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Potential for rogue admin creation via XSS
---

The EU VAT Assistant for WooCommerce plugin for WordPress is susceptible to a Stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-103899. This flaw exists due to inadequate input sanitization and output escaping within the 'vat_number' parameter. The vulnerability allows an unauthenticated remote attacker to inject malicious JavaScript into the application. When a site administrator accesses the WooCommerce orders management interface to review an affected order, the stored payload executes within their browser context. This execution can be leveraged to perform unauthorized actions on behalf of the administrator, such as creating new rogue administrative accounts, thereby achieving full site takeover. All versions of the plugin up to and including 2.1.30.260413 are impacted.

## Attack Chain

1. An attacker identifies a publicly accessible order placement or profile update page that utilizes the vulnerable EU VAT Assistant plugin.
2. The attacker crafts a malicious JavaScript payload designed to perform unauthorized administrative actions, such as 'wp-admin/user-new.php' requests.
3. The attacker submits the order or profile information, injecting the JavaScript payload into the 'vat_number' parameter.
4. The application fails to sanitize or escape the input, storing the malicious script directly into the WordPress database.
5. A legitimate administrator navigates to the WooCommerce Orders section to review the transaction.
6. The browser renders the stored script while the administrator views the 'Edit Order' screen.
7. The script executes with the administrator's session privileges, allowing the attacker to create a new administrative user or modify system settings.
8. The attacker authenticates as the newly created administrative user to gain persistent access.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of an administrator's session. This leads to full site compromise, including the ability to exfiltrate sensitive data, inject unauthorized content, or create persistent administrative backdoors. Given the ubiquity of WooCommerce installations, the potential victim base is significant.

## Recommendation

Prioritized actions for security teams:
- Update The EU VAT Assistant for WooCommerce plugin to the latest version immediately following vendor guidance.
- Review WordPress audit logs for unexpected administrative account creation or changes to user roles.
- Implement a Content Security Policy (CSP) to restrict the execution of inline scripts and unauthorized external resources on the administrative dashboard.
- Audit administrative access to the WooCommerce backend, specifically monitoring for unusual 'wp-admin' traffic originating from external sources or suspicious browser agents.
