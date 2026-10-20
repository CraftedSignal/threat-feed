---
brief_id: brief-2026-10-16-hivepress-xss
event_id: brief-2026-10-16-hivepress-xss
revision: 1
activity_at: "2026-10-16T08:25:23Z"
title: Stored Cross-Site Scripting in HivePress WordPress Plugin
slug: 2026-10-hivepress-xss
description: An unauthenticated Stored Cross-Site Scripting (XSS) vulnerability in HivePress plugin versions 1.7.32 and earlier allows attackers to inject malicious scripts into attribute fields.
date: "2026-10-16T08:25:23Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against CVE details.
cpes:
  - cpe:2.3:a:hivepress:hivepress:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - web-application
vendors:
  - HivePress
products:
  - HivePress – Business Directory, Listings & Classified Ads Plugin (<= 1.7.32)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-109193
    cvss: 7.2
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109193
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade HivePress plugin to the latest version.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109193 remediation requirement.
  mitigation_plan:
    - priority: immediate
      action: Upgrade HivePress plugin to the version after 1.7.32.
      owner: IT Operations
      addresses: CVE-2026-109193
      evidence: Source explicitly notes 1.7.32 as the vulnerable version.
---

The HivePress - Business Directory, Listings & Classified Ads Plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in all versions up to and including 1.7.32. The vulnerability stems from insufficient input sanitization and output escaping when processing custom user attribute slugs (e.g., hp_custom_link). An unauthenticated attacker can exploit this by injecting arbitrary web scripts into user attribute values. Successful exploitation depends on an administrator having configured a custom user attribute where the display_format template includes the %value% token within an href, src, or style attribute context. When an unsuspecting user or administrator views a page where this attribute is rendered, the injected script executes within the victim's session.

## Impact

The vulnerability allows unauthenticated attackers to execute arbitrary JavaScript in the context of a user's browser session. If an administrator views an injected page, the attacker could potentially perform unauthorized administrative actions, capture session cookies, or redirect users to malicious domains. This affects any WordPress installation utilizing the HivePress plugin for business directories or classified ads with custom user attributes enabled.

## Recommendation

1. Upgrade the HivePress plugin to the latest version immediately to remediate the sanitization flaw (CVE-2026-109193).
2. Audit current HivePress custom user attribute configurations to identify if the %value% token is used within href, src, or style attributes.
3. Implement a strict Content Security Policy (CSP) to mitigate the impact of potential XSS attacks by restricting the sources from which scripts can be loaded and executed.
4. Use web application firewalls (WAF) to inspect incoming traffic for suspicious script tags or JavaScript event handlers injected into POST requests targeting attribute update endpoints.
