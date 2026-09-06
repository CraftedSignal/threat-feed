---
title: Authentication Bypass in HivePress Authentication Plugin
slug: 2026-09-hivepress-auth-bypass
description: The HivePress Authentication plugin for WordPress through version 1.1.4 is vulnerable to authentication bypass via improper validation of Facebook OAuth tokens, allowing unauthenticated attackers to impersonate arbitrary users.
date: "2026-09-06T03:35:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hivepress:authentication:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - authentication-bypass
  - wordpress
  - cve-2026-18056
vendors:
  - HivePress
products:
  - HivePress Authentication (<= 1.1.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550.001
    technique_name: Use Alternate Authentication Material
    evidence: This makes it possible for unauthenticated attackers to authenticate as any existing WordPress user, including administrators, whose email address is associated with a Facebook account for which the attacker can obtain any valid access token.
    confidence_band: high
cves:
  - id: CVE-2026-18056
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18056
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade HivePress Authentication plugin to version > 1.1.4
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18056 affects versions up to and including 1.1.4
  mitigation_plan:
    - priority: immediate
      action: Disable Facebook authentication via HivePress settings
      owner: IT Operations
      addresses: CVE-2026-18056
      evidence: Vulnerability is located in the Facebook authenticator component
---

The HivePress Authentication plugin for WordPress contains an authentication bypass vulnerability (CVE-2026-18056) affecting all versions up to and including 1.1.4. The vulnerability exists within the authenticate_user function, which handles Facebook identity resolution. When an attacker provides an access_token parameter, the plugin forwards this token to the Facebook Graph API. However, the plugin fails to perform necessary validation on the response, specifically omitting /debug_token verification and failing to compare the token's app_id against the locally configured hp_facebook_app_id. Consequently, the plugin trusts the Facebook Graph API response implicitly. An attacker who obtains a valid Facebook access token associated with a target's email address can use that token to authenticate as the target user within the WordPress site. If the target user is an administrator, this grants the attacker full administrative access to the WordPress environment.

## Impact

Successful exploitation allows unauthenticated attackers to hijack any user account within the WordPress installation, including administrator accounts. This leads to full site compromise, potential data exfiltration, and the ability to execute arbitrary code on the web server if administrative privileges are used to upload malicious themes or plugins. This affects any WordPress site utilizing the HivePress Authentication plugin for social login functionality.

## Recommendation

Prioritized actions for security teams:
- Immediately update the HivePress Authentication plugin to the latest version patched against CVE-2026-18056.
- If immediate patching is not possible, disable the Facebook authentication feature within the HivePress plugin settings.
- Audit WordPress user accounts for suspicious login activity or anomalous administrative actions originating from unknown IP addresses, particularly those associated with successful authentication events recorded by the plugin.
- Review web server access logs for repeated HTTP requests to the authentication endpoint containing the 'access_token' parameter, which may indicate testing or exploitation attempts.
