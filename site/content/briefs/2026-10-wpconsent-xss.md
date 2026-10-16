---
title: Stored Cross-Site Scripting in WPConsent WordPress Plugin
slug: 2026-10-wpconsent-xss
description: The WPConsent WordPress plugin up to version 1.1.9 is vulnerable to stored Cross-Site Scripting (XSS) via mXSS, allowing unauthenticated attackers to execute arbitrary scripts in a user's browser session.
date: "2026-10-16T08:25:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wpconsent:cookie_banner_&_cookie_consent_for_privacy_compliance:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - wordpress
  - web-application
  - cms
vendors:
  - WPConsent
products:
  - WPConsent – Cookie Banner & Cookie Consent for Privacy Compliance (<= 1.1.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-97640
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97640
rules:
  - title: Detect CVE-2026-97640 Exploitation - Debug Parameter Usage
    description: Detects unauthenticated requests to the site using the wpconsent_debug=1 parameter, which is a required step for calculating injection offsets in the WPConsent XSS vulnerability.
    platform: sigma
    severity: medium
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
    - action: Audit installed WordPress plugins for WPConsent version <= 1.1.9
      owner: IT Operations
      due: 24h
      evidence: Source document identifies version <= 1.1.9 as vulnerable
    - action: Deploy the debug parameter detection rule to identify reconnaissance attempts
      owner: SOC
      due: 24h
      evidence: Exploit chain relies on debug parameter usage for injection offset confirmation
  mitigation_plan:
    - priority: immediate
      action: Upgrade WPConsent to the latest patched version
      owner: IT Operations
      addresses: CVE-2026-97640
      evidence: Plugin vulnerable in versions <= 1.1.9
---

The WPConsent - Cookie Banner & Cookie Consent for Privacy Compliance (GDPR / CCPA / EU Compliance Cookie Notice) plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in all versions up to, and including, 1.1.9. The vulnerability arises due to insufficient input sanitization and output escaping when the "Script Blocking" feature is active. An unauthenticated attacker can exploit this via mutation XSS (mXSS), specifically by leveraging the plugin's Simple HTML DOM Parser to manipulate how content is rendered. This flaw allows an attacker to inject arbitrary web scripts into WordPress pages, which then execute when an unsuspecting user visits the affected page. The exploit requires chaining two specific comment submissions and using a debug parameter to verify injection offsets, posing a significant risk to site administrators and users.

## Attack Chain

1. Attacker enables or identifies a target WordPress site using the vulnerable WPConsent plugin with the "Script Blocking" feature enabled.
2. Attacker performs an unauthenticated request to the site with the parameter `wpconsent_debug=1` to retrieve the deterministic `___noise___` restoration key and determine the current injection offset.
3. Attacker submits the first comment containing malicious event-handler syntax (e.g., `onmouseover`) embedded inside a permitted `<code>` HTML element.
4. Attacker submits a second, coordinated comment containing the required `___noise___` restoration key placed within an allowed `<abbr title="">` attribute.
5. The plugin's Simple HTML DOM Parser processes these comments, causing the stored payloads to mutate and break out of the intended HTML tag structure.
6. The injected script is successfully stored on the server side as part of the comment section of a post or page.
7. A legitimate user or administrator visits the page containing the malicious comments.
8. The browser renders the mutated HTML, triggering the execution of the attacker's script in the context of the user's browser session.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a victim's browser session. This can lead to the theft of session cookies, administrative account takeover, unauthorized modification of site content, or the redirection of users to malicious external domains. As this plugin is designed for privacy compliance, an attacker could potentially weaponize it to target users who are already providing consent, leading to significant privacy and security compromises across the affected WordPress installation.

## Recommendation

1. Upgrade the WPConsent plugin to the latest version immediately to remediate the insufficient sanitization of comment content.
2. Disable the "Script Blocking" feature within the WPConsent plugin settings until a patch is applied if immediate updating is not possible.
3. Monitor web server access logs for anomalous requests containing the `wpconsent_debug=1` parameter, as this is a precursor for the attack chain.
4. Review comment moderation logs for suspicious activity, particularly multiple coordinated comments from the same source.
