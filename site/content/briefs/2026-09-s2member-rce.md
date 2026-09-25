---
title: Remote Code Execution in s2Member WordPress Plugin
slug: 2026-09-s2member-rce
description: An unauthenticated remote code execution vulnerability (CVE-2026-19804) exists in the s2Member WordPress plugin, allowing attackers to execute code via the first_name parameter when combined with a leaked proxy verification key.
date: "2026-09-25T08:57:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:s2member:excellent_for_all_kinds_of_memberships_content_restriction_paywalls_member_access_subscriptions:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - web-application
  - rce
  - cve-2026-19804
vendors:
  - s2Member
products:
  - s2Member – Excellent for All Kinds of Memberships, Content Restriction Paywalls & Member Access Subscriptions (<= 260814)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to execute code on the server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The flaw exists within the Signup Tracking Codes template functionality... enabling arbitrary PHP code injection.
    confidence_band: high
cves:
  - id: CVE-2026-19804
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19804
rules:
  - title: Detects CVE-2026-19804 Exploitation - PHP Code Injection in s2Member
    description: Detects attempted RCE exploitation of CVE-2026-19804 where PHP tags are injected into the first_name parameter of s2Member.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
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
    - action: Upgrade s2Member to a version beyond 260814
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerability exists in versions up to 260814
  hunt_leads:
    - lead: Look for PayPal Checkout AJAX responses in web logs
      technique_id: T1190
      data_needed:
        - Webserver access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Key is exposed in plaintext in the JSON response of any PayPal Checkout AJAX request
  mitigation_plan:
    - priority: immediate
      action: Disable Signup Tracking Codes template feature if not required
      owner: IT Operations
      addresses: CVE-2026-19804
      evidence: Vulnerability requires Signup Tracking Codes template containing the %%first_name%% placeholder
---

The s2Member plugin for WordPress (versions 260814 and earlier) contains a critical remote code execution (RCE) vulnerability identified as CVE-2026-19804. The flaw exists within the Signup Tracking Codes template functionality. If a site administrator has configured this template to use the %%first_name%% placeholder, user input submitted to the 'first_name' parameter is passed through an unsafe 'eval' function without sufficient sanitization. The esc_refs() function fails to strip PHP tags, enabling arbitrary PHP code injection. 

Successful exploitation requires two conditions: the site must have an active Signup Tracking Codes template containing the specified placeholder, and the attacker must obtain the site-global proxy verification key. This key is disclosed in plaintext within the JSON response of any PayPal Checkout AJAX request on the affected site. This vulnerability allows an unauthenticated attacker to execute code in the context of the web server.

## Attack Chain

1. Attacker monitors public-facing traffic for PayPal Checkout AJAX requests on the target site.
2. Attacker intercepts the JSON response to capture the plaintext site-global proxy verification key.
3. Attacker identifies a site where the s2Member plugin is configured with a Signup Tracking Codes template using the %%first_name%% placeholder.
4. Attacker crafts a malicious payload containing PHP tags and injects it into the 'first_name' parameter.
5. The plugin fails to sanitize the malicious input, passing the payload directly into an eval-based template substitution process.
6. The server interprets the injected PHP code, executing it with the privileges of the web server process.
7. Attacker gains unauthorized remote code execution, potentially leading to total system compromise or further lateral movement.

## Impact

Successful exploitation results in full unauthenticated remote code execution on the WordPress server. This allows for data exfiltration, modification of site content, installation of backdoors, or pivoting into the internal network. The scope of impact includes any WordPress instance using the vulnerable s2Member plugin versions up to 260814 with the documented Signup Tracking Codes feature enabled.

## Recommendation

Prioritize the immediate update of the s2Member plugin to a version beyond 260814 that addresses CVE-2026-19804. Monitor web server logs for HTTP POST requests to s2Member endpoints containing PHP syntax in the 'first_name' field. Investigate logs for unauthorized access to PayPal Checkout AJAX responses, which may indicate an attacker harvesting proxy verification keys. Implement a Web Application Firewall (WAF) rule to block common PHP tag sequences (e.g., <?php, <?) within the 'first_name' parameter for this specific plugin.
