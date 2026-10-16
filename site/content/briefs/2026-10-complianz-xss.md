---
title: Stored Cross-Site Scripting in Complianz GDPR/CCPA Cookie Consent Banner
slug: 2026-10-complianz-xss
description: The Complianz GDPR/CCPA Cookie Consent Banner plugin for WordPress (<= 7.5.5) is vulnerable to Stored XSS due to improper input sanitization, allowing unauthenticated attackers to execute arbitrary scripts via comment content.
date: "2026-10-16T04:24:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:complianz:gdpr_ccpa_cookie_consent_banner:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - wordpress
  - cve-2026-97339
vendors:
  - Complianz
products:
  - Complianz GDPR/CCPA Cookie Consent Banner (<= 7.5.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The exploit bypasses WordPress's wp_kses comment sanitization because the payload uses only allow-listed tags and hides executable tokens inside quoted attribute values.
    confidence_band: high
cves:
  - id: CVE-2026-97339
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97339
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Complianz GDPR/CCPA Cookie Consent Banner to a version > 7.5.5
      owner: IT Operations
      due: 24h
      evidence: Source confirms versions 7.5.5 and below are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Enable strict comment moderation for the WordPress site
      owner: Security Operations
      addresses: CVE-2026-97339
      evidence: The XSS is only realized after the comment is approved
---

The Complianz GDPR/CCPA Cookie Consent Banner plugin for WordPress, in versions 7.5.5 and below, contains a critical Stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-97339). The flaw originates from the yotu-wp Cookie-Blocker filter's failure to properly sanitize and escape input within comment content. An unauthenticated attacker can leverage this by crafting a comment that bypasses the standard WordPress wp_kses sanitization engine. By embedding executable JavaScript tokens within otherwise permitted HTML attribute values, the payload remains dormant until the plugin's output-buffer filter executes a str_replace() operation. This transformation inadvertently modifies the DOM, breaking out of the attribute context and enabling script execution. Because the payload triggers only after the comment is approved, this vector necessitates interaction between an attacker and a site moderator or an automated moderation workflow, posing a significant risk for session hijacking and malicious redirects on affected WordPress sites.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a victim's browser session. If a site administrator or privileged user views an affected page, the attacker could potentially perform actions on their behalf, steal session cookies, or inject malicious content into the site. The vulnerability affects all WordPress installations utilizing versions 7.5.5 or earlier of the plugin.

## Recommendation

1. Upgrade the Complianz GDPR/CCPA Cookie Consent Banner plugin to the latest available version beyond 7.5.5 immediately.
2. Implement strict moderation policies for user comments, especially for unauthenticated or anonymous accounts, to prevent the injection of malicious payloads until an update can be applied.
3. Review audit logs for suspicious comment content that contains unusual attribute strings or obfuscated JavaScript patterns.
