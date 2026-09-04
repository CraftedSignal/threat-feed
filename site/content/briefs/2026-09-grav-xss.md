---
title: Stored Cross-Site Scripting in Grav Shortcode Core
slug: 2026-09-grav-xss
description: Grav Shortcode Core versions prior to 6.2.5 are vulnerable to stored cross-site scripting (XSS) due to improper input sanitization in the [lorem] and [details] tags.
date: "2026-09-04T13:25:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getgrav:shortcode_core:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
vendors:
  - Grav
products:
  - Shortcode Core (< 6.2.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Grav Shortcode Core before 6.2.5 contains stored cross-site scripting vulnerabilities in the [lorem] tag parameter and [details] summary parameter.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.004
    technique_name: 'Server Software Component: Web Shell'
    evidence: Attackers with page-edit access can inject arbitrary HTML and JavaScript that executes in the browsers of all page visitors, including administrators.
    confidence_band: high
cves:
  - id: CVE-2026-85599
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85599
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Grav Shortcode Core to 6.2.5 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-85599 patch availability
  mitigation_plan:
    - priority: immediate
      action: Patch Shortcode Core to version 6.2.5
      owner: IT Operations
      addresses: CVE-2026-85599
      evidence: NVD vulnerability details
---

Grav Shortcode Core, a plugin for the Grav CMS, contains stored cross-site scripting (XSS) vulnerabilities affecting versions prior to 6.2.5. The vulnerability arises from insufficient sanitization of parameters within the [lorem] and [details] shortcodes, which are rendered directly into HTML without proper escaping. An attacker possessing page-editing privileges can inject malicious JavaScript into these tags. When other users or administrators visit the compromised page, the injected payload executes in their browser session. This allows for session hijacking, unauthorized actions performed on behalf of the victim, or credential theft. Given that administrators are susceptible to this attack, successful exploitation could lead to full site compromise if the attacker elevates privileges by targeting a logged-in administrative session.

## Impact

Successful exploitation results in the execution of arbitrary JavaScript in the browsers of users viewing the injected content. This poses a significant risk to the integrity and confidentiality of the CMS, particularly if administrative users view the compromised pages. It may lead to full site takeover through the unauthorized execution of administrative actions.

## Recommendation

Prioritized actions for administrators:
- Upgrade the Grav Shortcode Core plugin to version 6.2.5 or later immediately.
- Review all existing content pages for suspicious use of [lorem] or [details] tags if page-editing privileges have been shared with untrusted users.
- Audit user roles and permissions to ensure that page-edit capabilities are restricted to authorized personnel.
