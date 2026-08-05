---
title: Stored XSS Vulnerability in VikRentItems WordPress Plugin
slug: 2026-08-vikrentitems-xss
description: The VikRentItems WordPress plugin contains a stored XSS vulnerability in the checkout booking form allowing unauthenticated attackers to execute arbitrary scripts in the administrative backend.
date: "2026-08-05T08:06:14Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WordPress
products:
  - VikRentItems – Flexible Rental Management System
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-16143
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16143
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update VikRentItems plugin to the latest version to mitigate CVE-2026-16143.
      owner: IT Operations
      due: 48h
      evidence: NVD advisory identifies versions <= 1.2.1 as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Patch plugin versions identified as vulnerable.
      owner: IT Operations
      addresses: CVE-2026-16143
      evidence: NVD vulnerability disclosure.
---

The VikRentItems Flexible Rental Management System plugin for WordPress (versions 1.2.1 and earlier) contains a critical stored Cross-Site Scripting (XSS) vulnerability. The flaw exists within the saveorder() function, which fails to adequately sanitize the customer email input field. Specifically, the plugin utilizes sanitize_text_field(), which does not properly neutralize HTML attribute-breaking characters such as double quotes. 

When a user submits a booking, the malicious input is stored in the database. The vulnerability is triggered when an administrator or privileged user views the order within the backend. The editorder template echoes the stored email value directly into an HTML input element's value attribute without applying esc_attr(). This allows an unauthenticated attacker to inject JavaScript payloads that will execute in the browser session of the administrator, potentially leading to unauthorized actions or session hijacking.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of an administrator's browser session. This can be used to capture session cookies, perform unauthorized administrative operations, or redirect users to malicious sites, compromising the integrity of the WordPress backend.

## Recommendation

- Update the VikRentItems plugin to the latest available version provided by the vendor to receive the security patch.
- Review backend access logs for suspicious input patterns in booking checkout requests.
- Audit administrative sessions for unauthorized activities following the identification of malicious XSS payloads in order management interfaces.
