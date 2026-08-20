---
title: Reflected Cross-Site Scripting in Wagtail Dynamic Image URL Generator
slug: 2026-08-wagtail-xss
description: A reflected cross-site scripting (XSS) vulnerability in the Wagtail admin interface (CVE-2026-54263) allows an authenticated editor to execute arbitrary JavaScript in the context of a higher-privileged administrator.
date: "2026-08-20T19:13:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:torchbox:wagtail:*:*:*:*:*:*:*:*
vendors:
  - Wagtail
products:
  - Wagtail (7.3.x, 7.4.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: A user with a limited-permission editor account for the Wagtail admin could craft a URL that, when viewed by a user with higher privileges, could perform actions with that user's credentials.
    confidence_band: high
cves:
  - id: CVE-2026-54263
    cvss: 7.3
    epss: 0.00203
references:
  - https://github.com/advisories/GHSA-23m2-mghx-vqmf
  - https://docs.wagtail.org/en/stable/advanced_topics/images/image_serve_view.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Wagtail to version 7.3.3 or 7.4.2
      owner: IT Operations
      due: 48h
      evidence: Patched versions have been released as Wagtail 7.3.3 and 7.4.2.
  mitigation_plan:
    - priority: immediate
      action: Implement URL pattern override in urls.py
      owner: IT Operations
      addresses: CVE-2026-54263
      evidence: Workaround available by adding code to urls.py to disable the admin dynamic image preview functionality
---

Wagtail versions 7.3.0 through 7.3.2 and 7.4.0 through 7.4.1 are affected by a reflected cross-site scripting (XSS) vulnerability in the dynamic image URL generator view. The vulnerability resides within the Wagtail admin interface and allows a user with limited permissions, such as an editor, to craft a malicious URL. When a high-privilege user, such as an administrator, accesses this URL while logged into the admin interface, the malicious script is executed in their session context. This can lead to unauthorized administrative actions being performed on behalf of the victim. The flaw affects all Wagtail installations, regardless of whether the specific dynamic image serve view is enabled. Wagtail has released versions 7.3.3 and 7.4.2 to address this issue.

## Impact

The vulnerability poses a significant risk to the integrity of the Wagtail CMS by enabling privilege escalation through session hijacking or unauthorized administrative action. If exploited, an attacker could manipulate content, change site settings, or create new administrative accounts. The attack requires the attacker to have at least a low-privileged editor account, limiting the scope to internal threats or compromised low-level accounts.

## Recommendation

Prioritized actions for security teams:
- Upgrade Wagtail instances to version 7.3.3 or 7.4.2 immediately to remediate CVE-2026-54263.
- If upgrading is not immediately possible, implement the URL pattern workaround in 'urls.py' provided by the vendor to disable the vulnerable 'generate_url/output/' endpoint.
- Audit Wagtail admin access logs for abnormal requests to '/admin/images/*/generate_url/output/' originating from non-administrator user accounts.
