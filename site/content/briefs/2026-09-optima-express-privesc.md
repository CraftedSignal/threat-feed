---
title: Privilege Escalation in Optima Express IDX WordPress Plugin
slug: 2026-09-optima-express-privesc
description: An unauthenticated privilege escalation vulnerability (CVE-2026-93901) in the Optima Express IDX plugin allows attackers to elevate a pre-registered 'optima-express' user account to the Author role.
date: "2026-09-25T10:52:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ihomefinder:optima_express_idx:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - privilege-escalation
  - web-application
vendors:
  - iHomefinder
products:
  - Optima Express IDX (<= 8.7.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation of Privilege Escalation
    evidence: The provisionBlogCredentials function ... unconditionally calling $user->set_role('author') ... makes it possible for unauthenticated attackers to escalate a pre-registered optima-express account to the Author role.
    confidence_band: high
cves:
  - id: CVE-2026-93901
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93901
rules:
  - title: Detect CVE-2026-93901 Exploitation - Unauthorized AJAX Call
    description: Detects unauthorized attempts to trigger the vulnerable ihf_clear_cache AJAX action in Optima Express IDX plugin
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
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Disable open user registration on WordPress sites running Optima Express IDX
      owner: IT Operations
      due: 24h
      evidence: Exploitation requires open user registration to be enabled on the target site.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Optima Express IDX to a patched version beyond 8.7.5
      owner: IT Operations
      addresses: CVE-2026-93901
      evidence: Vulnerable in all versions up to, and including, 8.7.5.
---

The Optima Express IDX plugin for WordPress, in all versions up to and including 8.7.5, contains a critical privilege escalation vulnerability. The flaw exists within the `provisionBlogCredentials()` function located in `iHomefinderAdmin.php`. This function is reachable via the `wp_ajax_nopriv_ihf_clear_cache` AJAX action, which lacks necessary capability checks, nonce verification, and ownership validation. 

The exploitation path follows the chain `iHomefinderAjaxHandler::clearCache()` to `activateAuthenticationToken()`, `getAuthenticationInfo()`, and finally `provisionBlogCredentials()`. The function unconditionally executes `$user->set_role('author')` for any user account matching the login `optima-express`. If a WordPress site has open user registration enabled, an attacker can register this specific username before the plugin performs its internal integration setup. By doing so, the attacker successfully gains 'author' privileges, including the ability to publish and edit posts, and gains unauthorized access to the `/wp-json/optima-express/v1/blog-post` REST API endpoint.

## Attack Chain

1. The attacker identifies a WordPress site with the Optima Express IDX plugin installed and open registration enabled.
2. The attacker registers a new WordPress user account using the username `optima-express`.
3. The attacker crafts a request to the `wp-admin/admin-ajax.php` endpoint.
4. The attacker specifies the `action` parameter as `ihf_clear_cache` to trigger the vulnerable code path.
5. The plugin's `iHomefinderAjaxHandler::clearCache()` method is invoked by the WordPress AJAX handler.
6. The execution chain proceeds to `provisionBlogCredentials()`, which identifies the attacker-controlled `optima-express` account.
7. The plugin executes `$user->set_role('author')` on the attacker's account.
8. The attacker now possesses 'author' level permissions, including REST API access for blog post management.

## Impact

Successful exploitation results in unauthorized privilege escalation to the Author role on the affected WordPress site. This grants the attacker the ability to create, edit, and publish posts, manage media uploads, and access specific plugin-restricted REST endpoints. This vulnerability poses a significant risk to site integrity and content management for any WordPress installation that allows public user registration while using the Optima Express IDX plugin.

## Recommendation

1. Immediately update the Optima Express IDX plugin to a version beyond 8.7.5 if a patch is available.
2. If an update is not currently available, disable the open user registration feature in WordPress settings (`Settings > General > Membership`) to prevent attackers from registering the `optima-express` username.
3. Monitor web server logs for suspicious POST requests to `admin-ajax.php` where `action=ihf_clear_cache`.
