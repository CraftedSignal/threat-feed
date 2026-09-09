---
title: Stored Cross-Site Scripting in WPBot WordPress Plugin
slug: 2026-09-wpbot-xss
description: The WPBot - AI ChatBot for Live Support, Lead Generation, AI Services plugin for WordPress contains a Stored Cross-Site Scripting (XSS) vulnerability in versions up to 8.7.3, allowing unauthenticated attackers to execute arbitrary web scripts.
date: "2026-09-09T06:48:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wpbot_project:wpbot:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-application-vulnerability
  - wordpress
  - cve-2026-83593
vendors:
  - WordPress
products:
  - WPBot – AI ChatBot for Live Support, Lead Generation, AI Services (<= 8.7.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages
    confidence_band: high
cves:
  - id: CVE-2026-83593
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83593
rules:
  - title: Detects CVE-2026-83593 Exploitation - XSS via conversation parameter
    description: Detects exploitation attempts against the WPBot plugin where the 'conversation' parameter contains common XSS injection patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch or disable the vulnerable WPBot plugin
      owner: IT Operations
      due: 24h
      evidence: Source document identifies plugin versions <= 8.7.3 as vulnerable
  hunt_leads:
    - lead: Search web logs for suspicious characters or script tags in POST requests to the WPBot conversation handler
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: XSS vulnerability in conversation parameter
---

The WPBot - AI ChatBot for Live Support, Lead Generation, AI Services plugin for WordPress is affected by a Stored Cross-Site Scripting (XSS) vulnerability identified as CVE-2026-83593. The vulnerability exists in the 'conversation' parameter and affects all versions up to and including 8.7.3. It stems from insufficient input sanitization and output escaping.

Defenders should note that the plugin's nonce check, intended to act as an access control mechanism, is rendered ineffective because it is localized into public-facing pages via the 'wp_localize_script' function. This allows unauthenticated attackers to bypass the check and inject malicious payloads into the conversation flow. Once stored, these scripts execute within the browser context of any user, including administrators, who views the compromised page. This vulnerability poses a significant risk to WordPress sites utilizing this plugin for customer support, as it can lead to session hijacking, unauthorized actions, or credential theft.

## Impact

Successful exploitation allows unauthenticated remote attackers to execute arbitrary JavaScript in the victim's browser session. If an administrator views the compromised page, the attacker could potentially take full control of the WordPress site. The plugin is widely used for lead generation and customer support, making this a high-impact vector for sites relying on interactive chatbot functionality.

## Recommendation

* Update the WPBot plugin to the latest available version (beyond 8.7.3) as soon as the vendor releases a patch.
* In the absence of a patch, disable the WPBot plugin on public-facing sites.
* Review access logs for POST requests containing JavaScript-like patterns in the 'conversation' parameter.
