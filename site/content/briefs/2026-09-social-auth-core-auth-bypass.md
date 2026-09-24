---
title: Authentication Bypass in social-auth-core VK App Backend
slug: 2026-09-social-auth-core-auth-bypass
description: The social-auth-core library fails to verify signatures in the vk-app backend when the auth_key parameter is missing, allowing attackers to impersonate arbitrary VK users.
date: "2026-09-24T20:04:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:python_social_auth:social_auth_core:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - web-vulnerability
  - python-social-auth
vendors:
  - python-social-auth
products:
  - social-auth-core (< 5.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Applications using this backend could treat unsigned attacker-controlled data as a verified VK identity.
    confidence_band: high
cves:
  - id: CVE-2026-57178
    cvss: 7.4
references:
  - https://github.com/advisories/GHSA-3c93-f73f-qc9h
  - https://github.com/python-social-auth/social-core/pull/1811
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57178
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade social-auth-core to version 5.0.0 or remove social_core.backends.vk.VKAppOAuth2 from authentication backends
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-57178 remediation
  mitigation_plan:
    - priority: immediate
      action: Remove social_core.backends.vk.VKAppOAuth2 from SOCIAL_AUTH_AUTHENTICATION_BACKENDS
      owner: IT Operations
      addresses: CVE-2026-57178
      evidence: Source workaround documentation
---

A vulnerability (CVE-2026-57178) exists in the social-auth-core library affecting the `vk-app` backend. When an application processes callback data from the VK platform, the library fails to enforce signature verification if the `auth_key` parameter is omitted from the request. This flaw allows an attacker to manipulate callback parameters such as `viewer_id`, `access_token`, `api_id`, and `api_result`. By crafting a malicious request without an `auth_key`, an attacker can inject arbitrary identity information, tricking the backend into authenticating them as any VK user. This vulnerability is specific to the `social_core.backends.vk.VKAppOAuth2` implementation. Defending against this requires upgrading to version 5.0.0 or later, or disabling the affected authentication backend entirely.

## Impact

Successful exploitation allows for full authentication bypass and identity impersonation within any web application that relies on the `vk-app` backend for user login. An attacker can gain unauthorized access to victim accounts, access user-specific data, and perform actions on behalf of legitimate users. The vulnerability affects all users of social-auth-core versions prior to 5.0.0 utilizing the VK App OAuth2 backend.

## Recommendation

* Upgrade social-auth-core to version 5.0.0 or later to ensure the `auth_key` parameter is strictly required for signature verification.
* If an immediate upgrade is not feasible, disable the vulnerable backend by removing `social_core.backends.vk.VKAppOAuth2` from the `SOCIAL_AUTH_AUTHENTICATION_BACKENDS` configuration in your application settings.
