---
title: 'CVE-2026-17123: SSRF in Royal Elementor Addons WordPress Plugin'
slug: 2026-08-royal-elementor-ssrf
description: The Royal Elementor Addons WordPress plugin is vulnerable to Server-Side Request Forgery due to improper handling of webhook URLs within the Form Builder widget, allowing authenticated contributors to send arbitrary outbound requests from the server.
date: "2026-08-16T06:24:58Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Royal Elementor Addons
products:
  - Royal Elementor Addons (<= 1.7.1064)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated attackers, with Contributor-level access and above, to make web requests to arbitrary locations originating from the web application.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: can be used to query and modify information from internal services.
    confidence_band: high
cves:
  - id: CVE-2026-17123
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17123
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Royal Elementor Addons plugin to a version > 1.7.1064
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-17123 patch requirement
  hunt_leads:
    - lead: Search webserver logs for POST requests to wp-admin/admin-ajax.php containing wpr_form_builder_webhook
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerable path is registered as an AJAX handler
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound traffic from WordPress web servers to internal IP ranges
      owner: IT Operations
      addresses: CVE-2026-17123
      evidence: SSRF enables internal network scanning
---

The Royal Elementor Addons plugin for WordPress (versions 1.7.1064 and below) contains a critical Server-Side Request Forgery (SSRF) vulnerability identified as CVE-2026-17123. The issue stems from the Form Builder widget, specifically its webhook functionality. When a user with Contributor-level access or higher previews a draft, the widget's render method saves a user-supplied URL into the 'wpr_webhook_url_{widget_id}' option. Subsequently, the AJAX handler 'wpr_form_builder_webhook' retrieves this value and executes an outbound request via 'wp_remote_post()'. Critically, this execution path fails to invoke existing internal security helpers designed to block requests to private or loopback IP addresses, nor does it enforce host allowlisting or scheme validation. This oversight enables an attacker to force the server to interact with internal network resources, potentially leading to unauthorized data access or the manipulation of internal services residing within the hosting environment.

## Impact

Successful exploitation allows authenticated attackers to perform SSRF attacks, enabling them to scan internal networks, interact with local services that lack external authentication, or exfiltrate sensitive configuration data from the internal infrastructure. Given the ubiquity of WordPress installations, this vulnerability poses a significant risk to organizations hosting internal or private services within the same network segment as their public web servers.

## Recommendation

* Immediately update the Royal Elementor Addons plugin to the latest available version beyond 1.7.1064, which contains the patch for CVE-2026-17123.
* Audit access logs for the 'wpr_form_builder_webhook' AJAX action to identify potentially malicious requests originating from Contributor-level user accounts.
* Implement strict egress filtering at the network level on web servers to prevent unauthorized connections from the application server to internal IP segments.
* Review all custom webhook integrations for similar 'wp_remote_post()' usage that bypasses standard sanitization helper functions.
