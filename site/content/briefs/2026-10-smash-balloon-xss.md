---
title: Stored Cross-Site Scripting and RCE in Smash Balloon Social Post Feed
slug: 2026-10-smash-balloon-xss
description: The Smash Balloon Social Post Feed WordPress plugin is vulnerable to Stored XSS that can be escalated to arbitrary plugin installation and remote code execution.
date: "2026-10-02T08:23:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:smashballoon:social_post_feed:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - rce
  - web-application-vulnerability
vendors:
  - Smash Balloon
products:
  - Social Post Feed – Simple Social Feeds for WordPress (<= 4.13.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts that will execute whenever an administrator accesses the feed builder preview page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The use of v-show rather than v-if means injected HTML — including onerror handlers — is evaluated in the DOM even when the comment section is not visually displayed.
    confidence_band: high
cves:
  - id: CVE-2026-93756
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93756
rules:
  - title: Detect CVE-2026-93756 Exploitation - Unauthorized Plugin Installation Attempt
    description: Detects potential exploitation attempts by monitoring requests to the cff_install_addon AJAX endpoint which lacks input validation for the source URL.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Social Post Feed plugin to version > 4.13.0
      owner: IT Operations
      due: 24h
      evidence: Source states all versions up to 4.13.0 are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Block or filter requests to cff_install_addon on the web server
      owner: IT Operations
      addresses: CVE-2026-93756
      evidence: Source identifies cff_install_addon as the target for RCE escalation
---

The Smash Balloon Social Post Feed (all versions up to and including 4.13.0) contains a critical security vulnerability involving insufficient input sanitization and output escaping. An unauthenticated attacker can perform a Stored Cross-Site Scripting (XSS) attack by posting a crafted message to a Facebook Page connected to the WordPress plugin. Because the plugin's Admin Builder Preview uses the v-show directive rather than v-if, injected HTML and JavaScript (such as onerror handlers) are rendered and executed in the administrator's browser context even when the content is hidden. Furthermore, this vulnerability can be chained with an insecure AJAX handler (cff_install_addon) in admin/addon-functions.php, which lacks URL validation. By forcing an authenticated administrator to interact with the feed builder, an attacker can leverage the XSS payload to trigger the installation of arbitrary, malicious plugins from an external URL, ultimately leading to server-side code execution.

## Attack Chain

1. Attacker posts a comment containing a malicious JavaScript payload to a Facebook Page connected to a target WordPress site.
2. The plugin synchronizes the malicious comment from Facebook into the WordPress database without sanitization.
3. A site administrator logs into the WordPress dashboard and navigates to the Social Post Feed plugin's Admin Builder Preview.
4. The plugin renders the malicious comment content in the DOM via the vulnerable v-show directive.
5. The injected JavaScript payload executes in the administrator's session.
6. The payload makes an AJAX request to the cff_install_addon handler (admin/addon-functions.php).
7. The handler processes the request using an attacker-supplied external URL to fetch and install a malicious plugin.
8. The malicious plugin is activated, granting the attacker full remote code execution on the WordPress server.

## Impact

Successful exploitation allows unauthenticated attackers to achieve remote code execution on the underlying server. This enables full site compromise, data exfiltration, and the ability to pivot into the host environment. All WordPress sites using the Social Post Feed plugin version 4.13.0 or earlier are susceptible to this vector.

## Recommendation

1. Immediately update the Social Post Feed - Simple Social Feeds for WordPress plugin to a version beyond 4.13.0 that addresses the sanitization and URL validation flaws.
2. Implement an aggressive Web Application Firewall (WAF) rule to block POST requests containing suspicious JavaScript strings or unexpected external URLs directed at the cff_install_addon AJAX endpoint.
3. Audit the WordPress administrative activity logs for unexpected plugin installations or activations, specifically looking for sources outside the official WordPress.org repository.
