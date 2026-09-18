---
title: Stored XSS Vulnerability in Jeg Kit for Elementor
slug: 2026-09-jeg-kit-xss
description: The Jeg Kit for Elementor plugin for WordPress contains a stored cross-site scripting vulnerability that allows unauthenticated attackers to execute arbitrary scripts when a specific widget is rendered.
date: "2026-09-18T12:05:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jegtheme:jeg_kit_for_elementor:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - web-application
vendors:
  - Jegtheme
products:
  - Jeg Kit for Elementor (<= 3.2.16)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The countdown frontend script to be enqueued and to initialize on any matching DOM element — including forged widget markup stored in comments.
    confidence_band: high
cves:
  - id: CVE-2026-18405
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18405
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Jeg Kit for Elementor to a version beyond 3.2.16
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-18405 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest patched version of Jeg Kit for Elementor
      owner: IT Operations
      addresses: CVE-2026-18405
      evidence: NVD vulnerability disclosure
---

The Jeg Kit for Elementor (Powerful Addons for Elementor, Widgets & Templates) plugin for WordPress contains a critical security flaw identified as CVE-2026-18405. The vulnerability resides in the insufficient sanitization and output escaping of user-supplied data within comment fields. All versions of the plugin up to and including 3.2.16 are affected. An unauthenticated attacker can exploit this flaw by injecting malicious JavaScript into a post's comments section. The payload remains dormant until a user views a page on the site that utilizes the Jeg Kit Countdown widget. Once the widget initializes, it forces the execution of the injected script within the context of the victim's browser, potentially allowing attackers to hijack sessions or perform unauthorized actions on behalf of the user.

## Impact

Successful exploitation of CVE-2026-18405 leads to stored XSS, allowing unauthenticated attackers to execute arbitrary web scripts in the browser of any user viewing a page containing the Jeg Kit Countdown widget. This poses a significant risk for administrative account takeover, data theft, and unauthorized site manipulation. The vulnerability affects all WordPress instances running Jeg Kit for Elementor version 3.2.16 or earlier.

## Recommendation

1. Update the Jeg Kit for Elementor plugin to the latest available version provided by Jegtheme to address the input sanitization flaw in CVE-2026-18405.
2. Audit comments sections on WordPress sites utilizing the Jeg Kit Countdown widget for suspicious markup or script tags.
3. Implement a strict Content Security Policy (CSP) to mitigate the impact of potential XSS vulnerabilities by restricting the sources from which scripts can be executed.
