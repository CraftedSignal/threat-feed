---
brief_id: brief-2026-10-31-social-login-auth-bypass
event_id: brief-2026-10-31-social-login-auth-bypass
revision: 1
activity_at: "2026-10-31T09:55:04Z"
title: 'Wp Social Login and Register Social Counter: Authentication Bypass (CVE-2026-103898)'
slug: 2026-10-social-login-auth-bypass
description: An authentication bypass vulnerability in the Wp Social Login and Register Social Counter plugin allows unauthenticated attackers to impersonate any site user, including administrators, by spoofing OAuth email callbacks.
date: "2026-10-31T09:55:04Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:wp_social_login_and_register_social_counter_project:wp_social_login_and_register_social_counter:*:*:*:*:*:wordpress:*:*
tags:
  - authentication-bypass
  - wordpress
  - plugin-vulnerability
products:
  - Wp Social Login and Register Social Counter (<= 3.2.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to obtain a fully authenticated session as any existing WordPress user, including Administrators, whose registered email address can be presented through a configured Facebook or Twitter login on the target site.
    confidence_band: high
cves:
  - id: CVE-2026-103898
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103898
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Disable Wp Social Login and Register Social Counter plugin version 3.2.2 and earlier.
      owner: IT Operations
      due: 4h
      evidence: Plugin is vulnerable to authentication bypass allowing complete account takeover.
  hunt_leads:
    - lead: Identify unauthorized authentication events via the social login endpoint.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation involves POST requests to /wp-json/wslu-social-login/type/.
  mitigation_plan:
    - priority: immediate
      action: Remove or disable the plugin until an update is provided by the developer.
      owner: IT Operations
      addresses: CVE-2026-103898
      evidence: Plugin lacks sufficient verification guards for OAuth email callbacks.
---

The Wp Social Login and Register Social Counter plugin for WordPress contains an authentication bypass vulnerability (CVE-2026-103898) affecting versions 3.2.2 and earlier. The flaw resides in the REST API callback registered at '/wp-json/wslu-social-login/type/{provider}/'. The plugin incorrectly trusts email addresses provided by OAuth providers (specifically Facebook and Twitter adapters) to identify users. Due to a logical failure where the 'emailVerified' check is a no-op, the plugin calls 'wp_set_auth_cookie()' to authenticate the attacker as the account associated with the provided email without requiring a password or additional proof of ownership.

## Impact
Successful exploitation grants an attacker full access to the target WordPress site as any user, including users with Administrator privileges. This impact is observed based on the logic of the vulnerable REST callback implementation.

## Recommendation
- Immediately disable the Wp Social Login and Register Social Counter plugin until a security update patching this authentication logic is verified and deployed.
- Audit the WordPress 'users' table and recent login logs for anomalous administrative access from unrecognized IP addresses or timestamps.
- If social login functionality is required, migrate to a reputable, actively maintained plugin and enforce strict multi-factor authentication (MFA) for all administrative accounts.
