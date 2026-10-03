---
title: Unauthenticated Arbitrary Shortcode Execution in Beaver Builder Plugin
slug: 2026-10-beaver-builder-shortcode
description: Beaver Builder Page Builder for WordPress (<= 2.11.0.5) is vulnerable to unauthenticated arbitrary shortcode execution via improper input validation in the Sidebar module.
date: "2026-10-03T08:54:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:beaver_builder:page_builder:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - wordpress
  - plugin-exploit
vendors:
  - Beaver Builder
products:
  - Beaver Builder Page Builder (<= 2.11.0.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can exploit this by injecting malicious shortcodes into widgets that accept user-controllable text.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This vulnerability allows for potential remote code execution or other unauthorized actions depending on the available shortcodes.
    confidence_band: high
cves:
  - id: CVE-2026-92084
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92084
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Beaver Builder plugin to patched version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-92084
  mitigation_plan:
    - priority: immediate
      action: Enable comment moderation for all widgets rendered in Beaver Builder Sidebar modules
      owner: IT Operations
      addresses: CVE-2026-92084
      evidence: Exploitation requires the target site to have a Beaver Builder page containing the Sidebar module populated with a widget that displays attacker-controllable text
---

The Beaver Builder Page Builder plugin for WordPress (versions up to and including 2.11.0.5) contains a critical security flaw involving improper input validation. The vulnerability allows unauthenticated attackers to execute arbitrary shortcodes within a WordPress environment. This occurs because the plugin's Sidebar module fails to sanitize or validate user-supplied values before passing them to the do_shortcode function. 

The exploitation path relies on the presence of a Beaver Builder page utilizing the Sidebar module, which contains a widget capable of rendering attacker-controllable text, such as the WordPress core Recent Comments widget. If the target environment has comment moderation disabled or if an attacker's crafted comment is approved, the malicious shortcode payload is injected and subsequently executed when the Sidebar module renders the widget. Successful exploitation can lead to a range of impacts, including unauthorized data access or remote code execution, depending on the capabilities of the shortcodes enabled on the target site.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary shortcodes on affected WordPress installations. This can lead to unauthorized information disclosure, privilege escalation, or remote code execution depending on the specific shortcodes available within the site's environment. This vulnerability affects all sites running Beaver Builder version 2.11.0.5 or earlier.

## Recommendation

1. Upgrade the Beaver Builder Page Builder plugin to a version patched against CVE-2026-92084 immediately.
2. Review site configurations for WordPress instances running affected versions, specifically checking for the presence of the Sidebar module on publicly accessible pages.
3. Implement strict comment moderation policies on WordPress sites to prevent unauthorized or untrusted content from being rendered in widgets.
4. Audit currently enabled WordPress shortcodes to assess the potential risk of arbitrary execution in the event of an exploit attempt.
