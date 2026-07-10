---
title: FreeScout Stored XSS Vulnerability in Mailbox Signatures (CVE-2026-40568)
slug: 2024-01-freescout-xss
description: A stored cross-site scripting (XSS) vulnerability exists in FreeScout versions prior to 1.8.213 within the mailbox signature feature due to an incomplete HTML tag blocklist and failure to remove event handler attributes.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - freescout
  - xss
  - cve-2026-40568
  - web-application
vendors:
  - FreeScout
products:
  - FreeScout
cves:
  - id: CVE-2026-40568
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40568
rules:
  - title: Detect FreeScout XSS Attempt via Mailbox Signature
    description: Detects attempts to inject potentially malicious HTML in FreeScout mailbox signatures by searching for specific HTML tags with event handler attributes.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: Detect FreeScout Mailbox Signature Update with Blocked Tags
    description: Detects attempts to inject blocked HTML tags in FreeScout mailbox signatures
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FreeScout, a self-hosted help desk and shared mailbox platform, is vulnerable to a stored XSS attack in versions prior to 1.8.213. The vulnerability resides in the mailbox signature feature, where the sanitization function `Helper::stripDangerousTags()` at `app/Misc/Helper.php:568` inadequately filters HTML tags and attributes. Specifically, it fails to remove event handler attributes and only blocks `script`, `form`, `iframe`, and `object` tags. An authenticated user possessing the `ACCESS_PERM_SIGNATURE` (`sig`) permission can inject malicious HTML, including tags like `<img>`, `<svg>`, and `<details>` with event handlers such as `onerror` or `onload`. This injected code is then executed whenever any agent or administrator opens a conversation in the affected mailbox. Successful exploitation can lead to session hijacking, phishing attacks, and email exfiltration. The vulnerability was patched in version 1.8.213.

## Attack Chain

1. An attacker authenticates to FreeScout with an account possessing the `ACCESS_PERM_SIGNATURE` permission.
2. The attacker navigates to the mailbox settings.
3. The attacker injects malicious HTML containing XSS payloads into the mailbox signature field. Example: `<img src=x onerror=alert(document.domain)>`.
4. The attacker saves the modified mailbox signature via `MailboxesController::updateSave()` at `app/Http/Controllers/MailboxesController.php:267`. The incomplete sanitization allows the malicious HTML to be stored in the database.
5. The signature is rendered as raw HTML via the Blade `{!! !!}` tag in `editor_bottom_toolbar.blade.php:6`.
6. The raw HTML is re-inserted into the DOM by jQuery `.html()` at `main.js:1789-1790`.
7. The injected event handler (e.g., `onerror`) is triggered when the HTML is rendered in a conversation view.
8. The attacker executes arbitrary JavaScript code within the context of the FreeScout application, potentially leading to session hijacking, phishing overlays, or further malicious actions like email exfiltration.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code within the FreeScout application. This can lead to a range of malicious activities, including session hijacking, phishing attacks against agents and administrators, and even email exfiltration. Since the vulnerability requires only the `ACCESS_PERM_SIGNATURE` permission, which can be delegated, the attack surface is broad. The CVSS v3.1 base score is 8.5, indicating a high severity.

## Recommendation

*   Upgrade FreeScout to version 1.8.213 or later to patch CVE-2026-40568.
*   Implement the "Detect FreeScout XSS Attempt via Mailbox Signature" Sigma rule to identify attempts to inject malicious HTML in mailbox signatures.
*   Review and restrict the `ACCESS_PERM_SIGNATURE` permission to only trusted users to minimize the attack surface.
*   Monitor web server logs for requests to `MailboxesController::updateSave()` (`app/Http/Controllers/MailboxesController.php:267`) containing potentially malicious HTML payloads.
