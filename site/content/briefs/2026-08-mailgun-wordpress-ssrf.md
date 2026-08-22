---
title: Unauthenticated SSRF in Mailgun for WordPress Plugin
slug: 2026-08-mailgun-wordpress-ssrf
description: An unauthenticated SSRF vulnerability in the Mailgun for WordPress plugin (<= 2.2.0) allows attackers to perform unauthorized API requests and potentially intercept password reset emails, leading to account takeover.
date: "2026-08-22T09:29:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - WordPress
products:
  - Mailgun for WordPress
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Mailgun for WordPress plugin for WordPress is vulnerable to Server-Side Request Forgery (SSRF) via path traversal in versions up to and including 2.2.0.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: including creating inbound email-forwarding routes that can intercept password reset emails, leading to administrator account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-78003
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78003
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Mailgun for WordPress plugin to version > 2.2.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-78003 vulnerability in plugin <= 2.2.0
---

The Mailgun for WordPress plugin is susceptible to a high-severity Server-Side Request Forgery (SSRF) vulnerability, tracked as CVE-2026-78003, affecting all versions up to and including 2.2.0. The vulnerability stems from insufficient input validation within the add_list() function. Specifically, the plugin processes user-controlled input from the $_POST['addresses'] parameter using only sanitize_text_field(), which fails to adequately block malicious input.

An unauthenticated remote attacker can leverage this flaw to send arbitrary POST requests to external Mailgun API endpoints. Because the plugin relies on the site's locally stored API key to authenticate these requests, the attacker can manipulate Mailgun routing configurations. A critical impact of this vulnerability is the ability to create unauthorized inbound email-forwarding routes, which can be configured to intercept password reset tokens, ultimately allowing an attacker to hijack administrator accounts. This flaw highlights the risks associated with improper handling of user-supplied data in administrative plugin functions.

## Attack Chain

1. The attacker identifies a target WordPress site running a vulnerable version (<= 2.2.0) of the Mailgun for WordPress plugin.
2. The attacker crafts a malicious HTTP POST request targeting the endpoint handling the add_list() functionality.
3. The attacker injects malicious payload data into the $_POST['addresses'] parameter to bypass input sanitization.
4. The plugin's add_list() function processes the crafted input, triggering an unauthorized server-side request.
5. The server acts as a proxy, sending a POST request to the Mailgun API authenticated with the compromised site's API key.
6. The attacker successfully interacts with the Mailgun API to create a malicious inbound routing rule.
7. The attacker triggers a password reset for a target administrator account on the WordPress site.
8. The attacker intercepts the password reset email via the newly created Mailgun route, resulting in full account takeover.

## Impact

Successful exploitation of CVE-2026-78003 can result in complete site compromise. By intercepting administrative password resets, attackers can gain elevated privileges within the WordPress application. This vulnerability poses a critical threat to any organization relying on the Mailgun for WordPress plugin for email delivery, as the potential for unauthorized data access and persistence via malicious email routing is high.

## Recommendation

- Update the Mailgun for WordPress plugin to a version beyond 2.2.0 immediately to apply the patch for CVE-2026-78003.
- Review all configured Mailgun inbound routes for unauthorized entries, specifically looking for new forwarding rules that may have been created without administrative knowledge.
- Rotate the Mailgun API key associated with the WordPress site if there is any suspicion that the site was targeted by exploitation attempts.
- Audit WordPress administrative activity logs for unexpected usage of the add_list() function or associated plugin administrative features by unauthorized sessions.
