---
title: Stored Cross-Site Scripting in WP Photo Album Plus Plugin
slug: 2026-10-wppa-xss
description: An unauthenticated stored XSS vulnerability in WP Photo Album Plus <= 9.3.03.002 allows attackers to inject malicious scripts via REQUEST_URI session history due to insecure output rendering.
date: "2026-10-10T09:51:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:wp_photo_album_plus:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
vendors:
  - WordPress
products:
  - WP Photo Album Plus (<= 9.3.03.002)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-96278
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96278
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade WP Photo Album Plus to a patched version.
      owner: IT Operations
      due: 48h
      evidence: Plugin vulnerable <= 9.3.03.002
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to sanitize URI requests containing HTML tags.
      owner: IT Operations
      addresses: CVE-2026-96278
      evidence: Input sanitization failure
---

The WP Photo Album Plus plugin for WordPress contains a stored Cross-Site Scripting (XSS) vulnerability affecting all versions up to and including 9.3.03.002. The vulnerability stems from improper sanitization of the REQUEST_URI session history and subsequent insecure output handling. While the plugin utilizes esc_url_raw(), this function fails to provide adequate protection as it retains HTML entities. The internal function wppaEntityDecode() inadvertently reverses this by converting entities back into active HTML tags. These tags are then processed by the jQuery('#wppa-modal-container').html() function, resulting in the execution of arbitrary JavaScript within the context of the user's browser. This flaw allows unauthenticated remote attackers to execute scripts in the sessions of unsuspecting users, potentially leading to session hijacking, administrative action spoofing, or unauthorized content modification.

## Attack Chain

1. Attacker identifies a target WordPress site running a vulnerable version of the WP Photo Album Plus plugin.
2. Attacker crafts a malicious HTTP request containing HTML entities designed to bypass esc_url_raw() filtering.
3. The malicious payload is injected into the REQUEST_URI, which the plugin captures as part of its session history logging mechanism.
4. The application stores the unauthenticated user's malicious REQUEST_URI in the backend database.
5. A victim user (such as an administrator) navigates to a page within the plugin that displays the session history.
6. The plugin retrieves the stored malicious URI and passes it through the flawed wppaEntityDecode() function.
7. The decoded payload is rendered into the DOM via the jQuery('#wppa-modal-container').html() sink.
8. The victim's browser executes the injected script, allowing the attacker to perform actions as the victim.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary web scripts in the browser of any user viewing the affected page. In WordPress environments, this commonly leads to full administrative account takeover if an administrator views the injected content, ultimately allowing for complete site compromise, data exfiltration, or defacement.

## Recommendation

1. Upgrade the WP Photo Album Plus plugin to the latest version, ensuring all security patches associated with CVE-2026-96278 are applied immediately.
2. Implement a Web Application Firewall (WAF) rule to inspect and block requests containing suspicious HTML patterns or script tags in the URI request parameters.
3. Monitor web access logs for anomalous requests containing URL-encoded characters or common XSS payloads directed at the WordPress site.
