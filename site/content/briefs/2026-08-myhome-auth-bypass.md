---
title: Authentication Bypass in MyHome Core Plugin for WordPress
slug: 2026-08-myhome-auth-bypass
description: The MyHome Core plugin for WordPress is vulnerable to authentication bypass via insecure AJAX handlers, allowing unauthenticated attackers to hijack arbitrary user accounts.
date: "2026-08-30T07:08:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:myhome:myhome_core:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - authentication-bypass
  - vulnerability
vendors:
  - WordPress
products:
  - MyHome Core plugin (<= 4.4.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: This makes it possible for unauthenticated attackers to generate an activation token for an unconfirmed user account and obtain a valid authentication cookie.
    confidence_band: high
cves:
  - id: CVE-2026-15980
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15980
rules:
  - title: Detects CVE-2026-15980 Exploitation - Suspicious AJAX Activation Request
    description: Detects exploitation attempts against the MyHome Core plugin by identifying POST requests to admin-ajax.php that may be invoking the vulnerable activate() or send_link() functions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1550
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade MyHome Core plugin to version > 4.4.5
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability entry
  hunt_leads:
    - lead: Look for POST requests to /wp-admin/admin-ajax.php with action=activate or action=send_link
      technique_id: T1550
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of vulnerable AJAX handlers
  mitigation_plan:
    - priority: immediate
      action: Disable frontend registration in MyHome theme settings
      owner: IT Operations
      addresses: CVE-2026-15980
      evidence: Source documentation of required configuration
---

The MyHome Core plugin for WordPress contains a critical authentication bypass vulnerability (CVE-2026-15980) affecting all versions up to and including 4.4.5. The vulnerability stems from two primary flaws: missing authorization checks in the send_link() AJAX handler and improper token validation within the activate() function. 

Attackers can exploit these flaws to generate a valid activation token for an unconfirmed user account and subsequently obtain a valid authentication cookie. This allows an unauthenticated actor to hijack any user account, including those with administrator privileges. The exploitation requires specific configuration: the MyHome theme must be operating in legacy or WPBakery mode with frontend registration and confirmation email functionality enabled. Additionally, the target user account must not have the 'myhome_agent_confirmed' metadata flag set. Because this vulnerability allows for complete site takeover, immediate remediation is required for all affected WordPress instances.

## Impact

Successful exploitation results in full account takeover, including administrative access. This grants attackers the ability to modify site content, inject malicious scripts, install additional backdoors, or exfiltrate sensitive data from the WordPress database. The scope includes any WordPress environment using the MyHome theme configured for frontend registration.

## Recommendation

- Update the MyHome Core plugin to the latest available version beyond 4.4.5 immediately to resolve CVE-2026-15980.
- Disable frontend registration or the confirmation email feature in the MyHome theme settings if updating is not immediately feasible.
- Audit user accounts for unauthorized sessions or unexpected changes in user metadata, specifically checking for the presence of the 'myhome_agent_confirmed' key.
- Implement strict access controls for site administration and monitor web server logs for suspicious POST requests targeting /wp-admin/admin-ajax.php related to the MyHome theme's AJAX handlers.
