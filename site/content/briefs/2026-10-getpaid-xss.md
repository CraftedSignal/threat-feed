---
title: Stored Cross-Site Scripting in GetPaid Plugin for WordPress
slug: 2026-10-getpaid-xss
description: The GetPaid plugin for WordPress contains a Stored Cross-Site Scripting vulnerability in the mmdwqzpoxadd parameter, allowing unauthenticated attackers to execute arbitrary scripts in an administrator's browser.
date: "2026-10-17T08:49:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getpaid:getpaid:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - GetPaid (<= 2.8.61)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: The stored payload fires when an administrator views the affected invoice's Payment Form Details metabox.
    confidence_band: high
cves:
  - id: CVE-2026-111110
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111110
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update GetPaid plugin to a version patched against CVE-2026-111110
      owner: IT Operations
      due: 48h
      evidence: Source document identifies version 2.8.61 as vulnerable
  hunt_leads:
    - lead: Search web logs for POST requests containing script tags or event handlers in the mmdwqzpoxadd parameter
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves improper input sanitization of the mmdwqzpoxadd parameter
  mitigation_plan:
    - priority: immediate
      action: Update to version > 2.8.61
      owner: IT Operations
      addresses: CVE-2026-111110
      evidence: NVD advisory
---

The Payment forms, Buy now buttons, and Invoicing System | GetPaid plugin for WordPress is susceptible to Stored Cross-Site Scripting (XSS) due to inadequate input sanitization and output escaping. Specifically, the 'mmdwqzpoxadd' parameter fails to properly filter user-supplied input, allowing unauthenticated attackers to inject malicious web scripts. The vulnerability is exacerbated by the plugin's insecure handling of the 'getpaid_form_nonce' value, which is exposed to all visitors through 'wp_localize_script' as 'WPInv.formNonce'. Consequently, an attacker does not require authentication or separate authorization tokens to carry out the injection. The injected payload executes within the context of an administrator's session whenever they view the Payment Form Details metabox for a compromised invoice. This flaw affects all plugin versions up to and including 2.8.61.

## Impact

Successful exploitation allows unauthenticated attackers to perform actions within the administrative context of the WordPress instance. This may lead to unauthorized modification of settings, elevation of privileges, or the theft of administrative session cookies, depending on the capabilities of the injected payload.

## Recommendation

Prioritized actions for security teams:
- Update the GetPaid plugin to a version beyond 2.8.61 immediately.
- Audit the WordPress environment for unauthorized plugin configurations or unusual activity in administrative payment form management.
- Review web server access logs for POST requests containing script-like structures in the 'mmdwqzpoxadd' parameter.
