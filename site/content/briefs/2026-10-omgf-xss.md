---
title: Stored XSS in OMGF WordPress Plugin
slug: 2026-10-omgf-xss
description: The OMGF WordPress plugin is vulnerable to stored Cross-Site Scripting via the 's' parameter in comments-atom feeds, allowing unauthenticated script injection in environments where web servers permit MIME-sniffing.
date: "2026-10-07T10:36:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:daanvandenbergh:omgf:*:*:*:*:*:wordpress:*:*
vendors:
  - Daan van den Bergh
products:
  - OMGF | GDPR/DSGVO Compliant, Faster Google Fonts. Easy. (<= 6.3.10)
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
    evidence: enabling MIME-sniffing browsers such as Chromium to execute the injected script
    confidence_band: high
cves:
  - id: CVE-2026-89417
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89417
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch OMGF plugin to a version > 6.3.10
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-89417
  mitigation_plan:
    - priority: immediate
      action: 'Configure web server to set X-Content-Type-Options: nosniff'
      owner: IT Operations
      addresses: CVE-2026-89417
      evidence: Success requires server serves .tmp without X-Content-Type-Options header
---

The OMGF | GDPR/DSGVO Compliant, Faster Google Fonts. Easy. plugin for WordPress is susceptible to Stored Cross-Site Scripting (XSS) due to insufficient input sanitization and output escaping within the comments-atom feed. The vulnerability, tracked as CVE-2026-89417, affects all versions up to and including 6.3.10. An unauthenticated attacker can inject arbitrary web scripts into the search parameter 's'. When a user navigates to the resulting injected page, the script executes in the context of the user's browser session. The exploit's success depends on the underlying web server configuration; specifically, if the server serves the generated .tmp files without explicit 'Content-Type' or 'X-Content-Type-Options' headers, MIME-sniffing browsers - such as those based on Chromium - will execute the injected payload. This configuration deficiency is common in default Apache and nginx/php-fpm deployments, posing a significant risk for WordPress sites utilizing this plugin.

## Attack Chain

1. The attacker identifies a target WordPress site using the vulnerable OMGF plugin version 6.3.10 or lower.
2. The attacker crafts a malicious HTTP GET request targeting the comments-atom feed.
3. The attacker injects a JavaScript payload into the 's' search parameter within the request.
4. The plugin fails to sanitize the input and stores the malicious script in a .tmp file.
5. The web server serves the .tmp file to a victim user's browser.
6. The web server omits 'Content-Type' or 'X-Content-Type-Options' headers in the response.
7. The browser performs MIME-sniffing and interprets the stored script as executable content.
8. The malicious script executes in the victim's session, potentially leading to session hijacking or credential theft.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a victim's browser session. This can lead to unauthorized actions performed on behalf of authenticated users, session token theft, or redirecting users to malicious websites. The impact is elevated on sites where administrators frequently access affected feeds.

## Recommendation

* Update the OMGF plugin to the latest version beyond 6.3.10 immediately upon release of a vendor patch.
* Implement strict Content-Security-Policy (CSP) headers on the web server to mitigate the impact of XSS by restricting the sources of executable scripts.
* Configure web servers (Apache or nginx/php-fpm) to explicitly send the 'X-Content-Type-Options: nosniff' header to prevent browser MIME-sniffing.
* Review web server logs for requests containing script-like characters or tags in the 's' query parameter.
