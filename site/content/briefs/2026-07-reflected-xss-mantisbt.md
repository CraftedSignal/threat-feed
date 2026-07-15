---
title: MantisBT Reflected XSS Vulnerabilities in admin/install.php (CVE-2026-52847)
slug: 2026-07-reflected-xss-mantisbt
description: MantisBT versions 2.28.3 and earlier are vulnerable to six reflected XSS injection points in the `/admin/install.php` script, which attackers can exploit without authentication to perform credential phishing, open redirects, and UI manipulation due to an incomplete Content Security Policy.
date: "2026-07-15T18:31:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - xss
  - web-vulnerability
  - credential-theft
  - phishing
  - open-redirect
vendors:
  - MantisBT
products:
  - composer/mantisbt/mantisbt (<= 2.28.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: MantisBT 2.28.3 and earlier contains six reflected XSS injection points in `/admin/install.php`. No authentication is required.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Defense Evasion
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: reflected XSS injection points...User-supplied parameters are echoed into HTML without escaping...A Content Security Policy (script-src 'self') prevents inline JavaScript execution, but the CSP is missing a form-action directive
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: 'Credential phishing: Attacker crafts a URL that renders a fake login form on the real MantisBT admin page. Admin credentials are submitted to an attacker-controlled server.'
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1204
    technique_name: User Execution
    evidence: 'Open redirect: Victim is silently redirected to a phishing or malware site.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-77x8-3v3h-hrhv
  - https://github.com/mantisbt/mantisbt/commit/0f32ceabadc745239754962df91a51d5d51e3fd7
  - https://github.com/mantisbt/mantisbt/commit/f2191a0d8ce438bf74171d496cf721dae025a5c0
  - https://mantisbt.org/bugs/view.php?id=37103
  - https://mantisbt.org/docs/master/en-US/Admin_Guide/html-desktop/#admin.install.postcommon
rules:
  - title: Detects CVE-2026-52847 Exploitation - MantisBT admin/install.php Reflected XSS
    description: Detects exploitation attempts against MantisBT CVE-2026-52847, a reflected XSS in `/admin/install.php` by monitoring for common XSS payload indicators in the URI query parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

MantisBT versions 2.28.3 and earlier contain critical reflected Cross-Site Scripting (XSS) vulnerabilities, designated CVE-2026-52847, within the `/admin/install.php` script. There are six distinct injection points where user-supplied parameters are echoed directly into the HTML response without proper escaping via the `print_test_result()` function. This vulnerability requires no prior authentication, making it easily exploitable. While a Content Security Policy (CSP) with `script-src 'self'` prevents direct inline JavaScript execution, the absence of a `form-action` directive in the CSP allows attackers to bypass this protection. This CSP misconfiguration enables sophisticated exploitation techniques such as credential-phishing form injection and `<meta>`-based open redirects, posing a significant risk to administrators. The vulnerability can lead to credential theft, silent redirection to malicious sites, and deceptive UI manipulation for social engineering purposes.

## Attack Chain

1. **Initial Reconnaissance**: Attacker identifies a MantisBT instance with `/admin/install.php` accessible, potentially using OSINT or vulnerability scanning tools.
2. **Vulnerability Identification**: Attacker confirms the presence of the reflected XSS vulnerability by sending crafted requests to `/admin/install.php` and observing unescaped input in the HTML response.
3. **Payload Crafting**: Attacker crafts a malicious URL containing an XSS payload designed to either inject a fake login form or an HTML `<meta>` refresh tag for redirection.
4. **Social Engineering**: Attacker sends the crafted malicious URL to a MantisBT administrator via email, instant message, or another communication vector (e.g., spearphishing).
5. **Victim Interaction**: The administrator clicks on the malicious URL, loading the vulnerable `/admin/install.php` page in their browser.
6. **XSS Execution**: The XSS payload in the URL executes, either rendering a fake login form that submits credentials to an attacker-controlled server or silently redirecting the user to a phishing or malware site.
7. **Credential Theft/Redirection**: The administrator's credentials are harvested by the attacker or the user is redirected to a malicious destination, leading to further compromise.

## Impact

Successful exploitation of CVE-2026-52847 can lead to severe consequences for organizations using affected MantisBT versions. The primary observed impacts include credential phishing, where an attacker can craft a URL that displays a convincing, but fake, login form on the legitimate MantisBT admin page, capturing administrator credentials when submitted. Additionally, the vulnerability can be used for open redirects, silently steering victims to attacker-controlled phishing or malware distribution sites. UI manipulation via CSS injection is also possible, allowing attackers to hide legitimate content and overlay malicious HTML elements for social engineering. While specific victim counts are not provided, any administrator interacting with a crafted URL is at risk, potentially leading to full compromise of the MantisBT instance and broader network access.

## Recommendation

* **Patch CVE-2026-52847 immediately** by upgrading MantisBT to a version patched by commits `0f32ceabadc745239754962df91a51d5d51e3fd7` or `f2191a0d8ce438bf74171d496cf721dae025a5c0`.
* **Implement the recommended workaround**: Remove the `/admin` directory from MantisBT instances if not actively used, as suggested in the MantisBT Admin Guide.
* **Deploy the Sigma rule below** to your SIEM to detect attempts to exploit the `/admin/install.php` path with XSS payloads.
* **Enable comprehensive web server logging** for the `webserver` category, capturing full URI paths and query parameters, to ensure the detection rule can identify malicious requests to `/admin/install.php`.
