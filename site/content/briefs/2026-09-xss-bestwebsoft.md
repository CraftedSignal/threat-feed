---
title: Stored XSS in BestWebSoft Contact Form to DB Plugin
slug: 2026-09-xss-bestwebsoft
description: The Contact Form to DB WordPress plugin (<= 1.7.5) is vulnerable to unauthenticated Stored Cross-Site Scripting via the cntctfrm_contact_dropdown parameter, allowing attackers to execute scripts in an administrator's browser session.
date: "2026-09-09T03:51:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bestwebsoft:contact_form_to_db_by_bestwebsoft_messages_database_plugin_for_wordpress:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - wordpress
  - cve-2026-13359
vendors:
  - BestWebSoft
products:
  - Contact Form to DB by BestWebSoft – Messages Database Plugin For WordPress (<= 1.7.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-13359
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13359
rules:
  - title: Detect CVE-2026-13359 - XSS Attempt via BestWebSoft Contact Form
    description: Detects exploitation attempts against CVE-2026-13359 by identifying script tags or event handlers in the cntctfrm_contact_dropdown POST parameter.
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
    - IT Operations
  immediate_actions:
    - action: Update BestWebSoft Contact Form to DB plugin to the version containing the patch for CVE-2026-13359.
      owner: IT Operations
      due: 24h
      evidence: Plugin version 1.7.5 is vulnerable; update required.
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to block malicious script injections in form parameters.
      owner: SOC
      addresses: CVE-2026-13359
      evidence: Source confirms XSS via cntctfrm_contact_dropdown.
---

The 'Contact Form to DB by BestWebSoft - Messages Database Plugin' for WordPress is susceptible to a Stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-13359. The vulnerability exists in all versions up to and including 1.7.5. It stems from insufficient input sanitization and output escaping on the 'cntctfrm_contact_dropdown' parameter. 

An unauthenticated attacker can submit a crafted payload through the plugin's contact form. This payload is stored in the database and subsequently executed when an administrator views the submission within the plugin's message manager interface (/wp-admin/admin.php?page=cntctfrmtdb_manager). Successful exploitation allows the attacker to execute arbitrary JavaScript in the context of the administrator's session, potentially leading to unauthorized administrative actions, session hijacking, or site redirection.

## Impact

Successful exploitation compromises the integrity and confidentiality of the WordPress administrative session. By executing scripts in the administrator's browser, an attacker could create new administrative accounts, modify site content, or perform other unauthorized actions. This vulnerability affects all WordPress instances using the specified plugin version.

## Recommendation

- Update the 'Contact Form to DB by BestWebSoft' plugin to the latest version immediately.
- Until patched, disable the affected plugin if it is not business-critical.
- Implement a Web Application Firewall (WAF) to inspect and block incoming HTTP requests containing suspicious script tags or JavaScript event handlers in the 'cntctfrm_contact_dropdown' parameter.
- Monitor web server access logs for anomalous POST requests to the contact form endpoint that contain HTML/JavaScript syntax.
