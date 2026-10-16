---
title: Unauthenticated Privilege Escalation in My Calendar WordPress Plugin
slug: 2026-10-my-calendar-priv-esc
description: The My Calendar WordPress plugin is vulnerable to unauthenticated privilege escalation via a reflected GET parameter that triggers arbitrary function calls, allowing attackers to overwrite administrator credentials.
date: "2026-10-16T06:24:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:my_calendar_project:my_calendar:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - My Calendar – Accessible Event Manager (<= 3.8.7)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The public mcs GET parameter is reflected into post content unsanitized, allowing an unauthenticated attacker to inject a nested [my_calendar above=...] shortcode, granting the attacker full wp-admin access.
    confidence_band: high
cves:
  - id: CVE-2026-104798
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104798
rules:
  - title: Detect CVE-2026-104798 Exploitation - Malicious GET Parameter Injection
    description: Detects exploitation attempts against My Calendar plugin by identifying suspicious shortcode injection patterns within the 'mcs' GET parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade My Calendar plugin to version 3.8.8 or later.
      owner: IT Operations
      due: 24h
      evidence: Plugin version 3.8.7 is explicitly stated as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rule to filter 'mcs' parameter for shortcode injection patterns.
      owner: Detection Engineering
      addresses: CVE-2026-104798
      evidence: Source analysis confirms injection via 'mcs' parameter.
---

The My Calendar - Accessible Event Manager plugin for WordPress, in versions 3.8.7 and earlier, contains a critical vulnerability (CVE-2026-104798) that permits unauthenticated privilege escalation. The vulnerability stems from an unsanitized reflected GET parameter, 'mcs', which is processed by the plugin before WordPress executes shortcode filtering. An attacker can inject a nested '[my_calendar]' shortcode, which subsequently triggers 'mc_generate_calendar_nav()'. This function improperly handles the 'above' attribute, splitting values by commas and passing them to 'call_user_func()' without any authorization or allowlist validation.

By crafting a malicious request, an attacker can invoke arbitrary PHP functions. A common exploitation chain involves targeting the 'edit_user()' function. Because the attacker-controlled shortcode parameters are passed to this function, PHP coercion can force the user ID argument to '1', effectively overwriting the administrator account credentials. Given that the default plugin page is often publicly accessible, this vulnerability provides a trivial path to full site administrative takeover.

## Attack Chain

1. The attacker identifies a WordPress site with the My Calendar plugin installed and enabled.
2. The attacker navigates to the public '/my-calendar/' page.
3. The attacker submits a crafted HTTP GET request containing the malicious 'mcs' parameter.
4. The plugin reflects the 'mcs' parameter into the application content without sanitization.
5. The WordPress environment executes 'do_shortcode', which processes the attacker-injected nested shortcode.
6. The 'mc_generate_calendar_nav()' function executes and splits the 'above' attribute.
7. 'call_user_func()' executes the attacker-defined function (e.g., 'edit_user') with malicious parameters.
8. The WordPress administrative account (user ID 1) is modified, granting the attacker full 'wp-admin' access.

## Impact

Successful exploitation results in full administrative compromise of the affected WordPress site. Because the vulnerability targets the site administrator (User ID 1), attackers gain complete control over site configuration, content, themes, and plugins. This impact is universal across all vulnerable installations where the plugin's default page remains published.

## Recommendation

* Immediately update the My Calendar - Accessible Event Manager plugin to a version later than 3.8.7.
* Audit WordPress user activity logs for unauthorized modifications to the administrative account (User ID 1), particularly via the 'edit_user' or 'wp_update_user' functions.
* Use the provided webserver detection rule to identify and block incoming malicious requests containing the 'mcs' injection pattern.
* Restrict public access to the '/my-calendar/' page or disable the plugin until a patch is applied if immediate updating is not possible.
