---
brief_id: brief-2026-10-27-qode-membership-auth-bypass
event_id: brief-2026-10-27-qode-membership-auth-bypass
revision: 1
activity_at: "2026-10-27T10:55:16Z"
title: 'Qode Membership: Authentication Bypass and Account Takeover (CVE-2026-92885)'
slug: 2026-10-qode-membership-auth-bypass
description: The Qode Membership WordPress plugin is vulnerable to authentication bypass via a typographic error in the Facebook OAuth token verification guard, allowing unauthenticated account takeover.
date: "2026-10-27T10:55:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - Qode Membership (<= 2.0.6.2)
cves:
  - id: CVE-2026-92885
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92885
---

The Qode Membership plugin for WordPress (all versions up to and including 2.0.6.2) contains a vulnerability in the `qode_membership_check_facebook_user` AJAX action. A typo in the `qode_membership_login_user_from_social_network` function (testing an undefined variable instead of the OAuth token) renders the verification logic ineffective. This allows unauthenticated attackers to bypass credential validation and log in as any WordPress user, including administrators, by providing a username in the `response[email]` parameter. Exploitation requires a `qode_validate_facebook_login` nonce, which is obtainable from public front-end pages containing the [qode_user_login] or [qode_user_register] shortcodes.
