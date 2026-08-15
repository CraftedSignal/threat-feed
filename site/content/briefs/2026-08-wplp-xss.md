---
title: Stored XSS Vulnerability in Cookie Banner for GDPR / CCPA Plugin
slug: 2026-08-wplp-xss
description: The WPLP Cookie Consent plugin for WordPress is vulnerable to stored cross-site scripting due to insufficient input validation in the regionArray parameter, allowing script injection by authenticated or unauthenticated attackers.
date: "2026-08-15T06:16:40Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WPLP
products:
  - Cookie Banner for GDPR / CCPA – WPLP Cookie Consent
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: injection of arbitrary scripts that execute in the context of the victim's browser session
    confidence_band: high
cves:
  - id: CVE-2026-13360
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13360
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update WPLP Cookie Consent plugin to the latest version to address CVE-2026-13360.
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable to stored XSS up to 4.3.5.
  mitigation_plan:
    - priority: immediate
      action: Disable 'Support Google Consent Mode (GCM)' in plugin settings if immediate patching is not possible.
      owner: IT Operations
      addresses: CVE-2026-13360
      evidence: Successful exploitation requires that the site administrator has enabled the 'Support Google Consent Mode (GCM)' setting.
---

The Cookie Banner for GDPR / CCPA - WPLP Cookie Consent plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in versions up to and including 4.3.5. The flaw exists due to improper input sanitization and output escaping within the 'regionArray' parameter. The vulnerability manifests in two ways: unauthenticated attackers can inject arbitrary web scripts if the 'Support Google Consent Mode (GCM)' feature is enabled by the administrator, and authenticated users with low-level privileges (such as Subscribers) can overwrite plugin settings because the AJAX handler lacks nonce or capability verification. This vulnerability enables attackers to execute malicious scripts in the context of a victim's browser, potentially leading to session hijacking, credential theft, or unauthorized actions performed on behalf of the victim.

## Attack Chain

1. Attacker identifies a WordPress site running an outdated version (<= 4.3.5) of the WPLP Cookie Consent plugin.
2. For authenticated exploitation, the attacker logs in as a low-privilege user (Subscriber).
3. The attacker sends a crafted AJAX request to the vulnerable plugin handler, targeting the 'regionArray' parameter.
4. The plugin fails to validate the request origin (no nonce) or user permissions (no capability check).
5. The malicious script is saved into the database as part of the plugin configuration.
6. The attacker waits for a high-privilege user or administrator to navigate to a page where the cookie banner is rendered.
7. The victim's browser fetches the malicious script from the database and renders it, leading to arbitrary JavaScript execution in the victim's session.

## Impact

Successful exploitation allows attackers to execute arbitrary JavaScript in the victim's browser session. This can lead to the exfiltration of session cookies, administrative actions taken without user consent, or the redirection of users to malicious websites. As the plugin is used for GDPR and CCPA compliance, it is widely deployed on public-facing websites, increasing the potential impact to both site administrators and site visitors.

## Recommendation

Prioritized actions for security teams:
- Update the Cookie Banner for GDPR / CCPA - WPLP Cookie Consent plugin to the latest patched version immediately.
- Review WordPress application logs for unusual AJAX requests targeting plugin settings or the 'regionArray' parameter.
- If immediate patching is not possible, disable the 'Support Google Consent Mode (GCM)' setting in the plugin configuration as a temporary mitigation.
- Monitor for unauthorized administrative actions originating from low-privilege (Subscriber) accounts.
