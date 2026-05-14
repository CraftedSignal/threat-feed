---
title: ethyca-fides fides.js DOM-based XSS Vulnerability
slug: 2026-05-ethyca-fides-xss
description: A DOM-based XSS vulnerability (CVE-2026-44541) exists in ethyca-fides' fides.js script, allowing arbitrary JavaScript execution in the embedding site's origin via crafted links when HTML-formatted descriptions are enabled.
date: "2026-05-14T19:06:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - dom-xss
  - ghsa
  - ethyca-fides
vendors:
  - ethyca
products:
  - fides.js
  - ethyca-fides
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-5qrq-9645-g5g2
  - CVE-2026-44541
rules:
  - title: Detect ethyca-fides fides.js DOM-based XSS Attempt
    description: Detects CVE-2026-44541 exploitation attempt — HTTP requests with the `fides_description` parameter containing HTML tags or JavaScript code, indicative of a DOM-based XSS attack against ethyca-fides fides.js.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect ethyca-fides fides.js Persistent DOM-based XSS via Cookie
    description: Detects CVE-2026-44541 exploitation — HTTP requests that include a 'fides_description' cookie containing HTML/JavaScript, indicating a possible persistent DOM-based XSS.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

A DOM-based XSS vulnerability has been identified in `fides.js`, the script used for rendering consent banners in Fides Enterprise deployments. The vulnerability (CVE-2026-44541) stems from a trust gap between the override mechanism, which allows banner fields like the description text to be modified via URL parameters, JavaScript globals, or cookies, and the HTML-formatted descriptions feature. When the `FIDES_PRIVACY_CENTER__ALLOW_HTML_DESCRIPTION` flag is enabled, the overridden description is rendered as live HTML without proper server-side sanitization, allowing attackers to inject arbitrary JavaScript code via a crafted link. This issue affects Fides Enterprise deployments using `fides.js` with HTML-formatted banner descriptions enabled. This allows attackers to execute arbitrary JavaScript code in the embedding site's origin. The vulnerability was patched in `ethyca/fides-privacy-center:2.84.5`.

## Attack Chain

1. An attacker crafts a malicious URL containing JavaScript code within the `fides_description` parameter (e.g., `<img src=x onerror="alert(\`DOM XSS in fides_description. Origin: ${document.domain}\`)">`).
2. The attacker distributes the malicious URL to potential victims through phishing or other social engineering techniques.
3. A victim clicks on the malicious URL, which loads the page where the consent banner is supposed to render.
4. `fides.js` retrieves the malicious JavaScript code from the `fides_description` parameter in the URL.
5. Because HTML-formatted descriptions are enabled (`FIDES_PRIVACY_CENTER__ALLOW_HTML_DESCRIPTION=true`), `fides.js` renders the malicious JavaScript code as live HTML without sanitization.
6. The victim's browser executes the injected JavaScript code within the context of the embedding website's origin.
7. (Optional) The attacker can leverage the XSS vulnerability to set a `fides_description` cookie, which persists the payload across all subdomains until the cookie is cleared.
8. The attacker gains the ability to read and modify data, issue requests, and render malicious content that appears to come from the site.

## Impact

Successful exploitation allows the attacker to execute arbitrary JavaScript code within the embedding site's origin, granting them the same privileges as the site's own scripts. This could lead to the theft of sensitive user data, modification of website content, redirection of users to malicious sites, or execution of arbitrary actions on behalf of the user. The cookie-based persistence variant increases the impact, as a single click can result in a persistent payload affecting all subdomains until cookies are cleared. The severity is rated HIGH with a CVSS v4 score of 7.0.

## Recommendation

*   Upgrade to `ethyca-fides` version 2.84.5 or later, or `fidesplus` version 2.84.6, which contain the patch for CVE-2026-44541.
*   As a workaround, set `FIDES_PRIVACY_CENTER__ALLOW_HTML_DESCRIPTION=false` on the Privacy Center container(s) to disable HTML-formatted descriptions, mitigating the XSS vulnerability.
*   Deploy the Sigma rule "Detect ethyca-fides fides.js DOM-based XSS Attempt" to identify potential exploitation attempts.
*   Monitor web server logs for requests containing the `fides_description` parameter with HTML tags or JavaScript code to detect potential exploitation attempts.
