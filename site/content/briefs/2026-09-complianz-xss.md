---
title: Stored XSS Vulnerability in Complianz WordPress Plugin
slug: 2026-09-complianz-xss
description: The Complianz GDPR/CCPA Cookie Consent Banner plugin is vulnerable to Stored Cross-Site Scripting (XSS) via the Elementor Cookie Blocker, allowing attackers to execute arbitrary JavaScript in the context of an administrator-approved comment.
date: "2026-09-18T10:06:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - xss
  - web-application
vendors:
  - Complianz
  - Elementor
products:
  - Complianz GDPR/CCPA Cookie Consent Banner (<= 7.5.4)
  - Elementor
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
    evidence: The Complianz GDPR/CCPA Cookie Consent Banner plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Comment Content.
    confidence_band: high
cves:
  - id: CVE-2026-83561
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83561
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Complianz GDPR/CCPA Cookie Consent Banner plugin to a version patched against CVE-2026-83561
      owner: IT Operations
      addresses: CVE-2026-83561
      evidence: Source reporting identifies this as a stored XSS vulnerability.
---

The Complianz GDPR/CCPA Cookie Consent Banner plugin for WordPress (versions 7.5.4 and below) contains a Stored Cross-Site Scripting (XSS) vulnerability. The issue stems from insufficient input sanitization and output escaping within the plugin's Elementor Cookie Blocker component. An unauthenticated attacker can inject malicious JavaScript into comment fields. The script is stored and subsequently executed when a site administrator approves the comment. For exploitation to succeed, the target site must have the Elementor plugin installed and the Complianz plugin configured to use the Twitter or Facebook cookie/script blocker regex features. This vulnerability represents a significant risk for administrative account takeover or session hijacking if an administrator views the malicious content.

## Impact

Successful exploitation allows for the execution of arbitrary JavaScript within the session of an authenticated administrator. This can lead to unauthorized actions performed on behalf of the administrator, data exfiltration, or the creation of new administrative accounts if the site configuration permits. The vulnerability affects all users running versions up to and including 7.5.4.

## Recommendation

1. Upgrade the Complianz GDPR/CCPA Cookie Consent Banner plugin to the latest version (post-7.5.4) as soon as a patch is available.
2. Implement strict Content Security Policy (CSP) headers to mitigate the impact of XSS by restricting the sources from which scripts can be loaded and executed.
3. Review and audit pending comments for suspicious content containing script tags or abnormal HTML attributes prior to approval.
