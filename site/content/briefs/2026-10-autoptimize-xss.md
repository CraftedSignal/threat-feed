---
title: Stored Cross-Site Scripting in Autoptimize WordPress Plugin
slug: 2026-10-autoptimize-xss
description: The Autoptimize WordPress plugin is vulnerable to Stored Cross-Site Scripting (XSS) due to improper sanitization of the REQUEST_URI path, allowing unauthenticated attackers to execute arbitrary scripts in the context of user sessions.
date: "2026-10-01T10:39:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:autoptimize:autoptimize:*:*:*:*:*:*:*:*
vendors:
  - Autoptimize
products:
  - Autoptimize (<= 3.1.15.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-14995
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14995
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Autoptimize plugin to version > 3.1.15.1
      owner: IT Operations
      due: 48h
      evidence: Source confirms vulnerability in versions <= 3.1.15.1
  mitigation_plan:
    - priority: immediate
      action: Disable 'Critical CSS' feature in Autoptimize settings
      owner: IT Operations
      addresses: CVE-2026-14995
      evidence: Exploitation requires the Critical CSS feature to be active
---

The Autoptimize plugin for WordPress (versions 3.1.15.1 and earlier) contains a security flaw in how it handles the REQUEST_URI path, resulting in a Stored Cross-Site Scripting (XSS) vulnerability. An unauthenticated attacker can exploit this by crafting malicious requests that include JavaScript payloads within the URI path. For the injection to succeed, the 'Critical CSS' feature must be active, and a valid API key must be configured in the plugin settings. These conditions trigger the ao_ccss_enqueue() function, which processes the malicious URI and stores the payload. When an administrative or authenticated user subsequently visits the affected page, the stored script executes in their browser, potentially leading to unauthorized actions, account takeover, or session hijacking.

## Impact

Successful exploitation allows unauthenticated attackers to inject malicious scripts into WordPress sites using the Autoptimize plugin. If the payload executes in the context of an administrator, the attacker could gain full control over the WordPress instance. This vulnerability affects any environment where the Critical CSS feature is enabled, posing a high risk for websites that rely on the plugin for front-end optimization.

## Recommendation

Update the Autoptimize plugin to a version greater than 3.1.15.1 to remediate CVE-2026-14995. If an immediate update is not feasible, disable the 'Critical CSS' feature in the plugin settings to mitigate the primary vector for unauthenticated exploitation until patching is complete. Monitor web access logs for unusual requests where the URI path contains script tags or common XSS payloads, focusing on POST requests targeted at the plugin's enqueue endpoint.
