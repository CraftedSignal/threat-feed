---
title: Stored XSS in Winter CMS and October CMS Backend
slug: 2026-08-winter-cms-xss
description: Authenticated backend users can perform stored cross-site scripting (XSS) by injecting malicious content into custom CSS settings in Winter CMS and October CMS.
date: "2026-08-12T16:49:14Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:octobercms:october:*:*:*:*:*:*:*:*
vendors:
  - Winter CMS
  - October CMS
products:
  - Winter CMS (1.2)
  - October CMS (3.7)
  - October CMS (4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Authenticated Backend Users with the backend.manage_editor permission can provide custom styles through Settings that are rendered on every backend page.
    confidence_band: high
cves:
  - id: CVE-2025-61674
    cvss: 6.1
    epss: 0.0019
references:
  - https://github.com/advisories/GHSA-vgp4-2fc4-qff2
  - https://github.com/wintercms/winter/commit/d28f0b9474af79cfaa80eeb9d691f7a7c4469720
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Winter CMS instances to v1.2.13
      owner: IT Operations
      due: 72h
      evidence: The issue has been patched in v1.2.13
  mitigation_plan:
    - priority: immediate
      action: Restrict backend management permissions to known trusted administrators
      owner: IT Operations
      addresses: CVE-2026-32258
      evidence: Winter CMS maintainers recommend that the backend.manage_editor permission only be granted to trusted administrators and developers.
---

Winter CMS and October CMS contain a stored cross-site scripting (XSS) vulnerability allowing authenticated users with high-level administrative permissions to inject malicious CSS. The issue resides in the backend settings for Markup Styles and Backend Styles. When these styles are compiled via the LESS CSS parser, the resulting output is not properly sanitized before being rendered on subsequent backend pages. This allows an attacker with 'backend.manage_editor' or 'backend.manage_branding' permissions to execute arbitrary JavaScript in the context of other administrative sessions. This vulnerability is tracked as CVE-2026-32258 in Winter CMS and CVE-2025-61674 in October CMS. The fix involves implementing the `strip_tags()` function on the output of the `renderCss()` method.

## Impact

The vulnerability poses a risk of account takeover and unauthorized actions performed on behalf of other administrative users, including super-administrators, due to the persistent nature of the XSS payload. Successful exploitation requires an attacker to already possess specific backend management permissions, limiting the attack surface to malicious insiders or compromised administrative accounts.

## Recommendation

- Upgrade to Winter CMS v1.2.13 or later to receive the `strip_tags()` patch for `renderCss()`.
- October CMS users should update to v3.7.13 or v4.0.12 to address the related CVE-2025-61674.
- Audit users assigned the 'backend.manage_editor' and 'backend.manage_branding' permissions to ensure only trusted personnel retain these rights.
- Review custom CSS and Markup Style settings in the backend for any unauthorized or suspicious injected scripts or CSS tags.
