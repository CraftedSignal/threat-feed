---
title: SiYuan Stored XSS via Malicious Bazaar Package README
slug: 2026-07-siyuan-xss
description: A stored Cross-Site Scripting (XSS) vulnerability, CVE-2026-54070, affects SiYuan versions up to 3.6.5, allowing a malicious third-party package author to embed JavaScript in package READMEs via an incomplete HTML sanitizer's blocklist, which executes in an Administrator's authenticated browser session upon viewing and interacting with the crafted README in the Bazaar marketplace, leading to API token theft and potential full workspace control.
date: "2026-07-10T19:42:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - code-execution
  - credential-theft
  - si-yuan
vendors:
  - siyuan-note
  - B3log
products:
  - siyuan-note/siyuan (<= 3.6.5)
  - go/github.com/siyuan-note/siyuan/kernel (< 0.0.0-20260628153353-2d5d72223df4)
  - b3log/siyuan (3.6.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: A malicious third-party Bazaar package author can inject JavaScript...A single malicious community package reaches every instance that views its listing.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A third-party Bazaar package author runs JavaScript in the Administrator's authenticated SiYuan origin...`alert(document.domain)` in the SiYuan origin on hover.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Pivot to `installBazaarPlugin` and kernel control
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Theft of the kernel API token (`conf.api.token`), which grants full Administrator API access.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Defacement
    evidence: gains full control of the workspace.
    confidence_band: med
cves:
  - id: CVE-2026-54070
    cvss: 7.1
    epss: 0.0018
references:
  - https://github.com/advisories/GHSA-w7cg-whh7-xp28
  - CVE-2026-54070
---

A critical stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-54070) has been identified in SiYuan, a note-taking application, affecting versions up to 3.6.5. This flaw allows a malicious third-party package author to inject arbitrary JavaScript into package READMEs displayed within SiYuan's Bazaar marketplace. The `lute` rendering engine's sanitizer, used to convert Markdown READMEs to HTML, employs an incomplete blocklist for event handlers, inadvertently permitting modern handlers like `onpointerover`, `onpointerdown`, and `onanimationstart` to bypass sanitization. When an Administrator, who has accepted the marketplace trust consent, views such a crafted package README in the marketplace and interacts with it (e.g., hovering the mouse), the embedded JavaScript executes within their authenticated session. This can lead to the theft of the kernel API token, which grants full Administrator API access, and potentially escalates to full control over the SiYuan workspace through actions like installing further malicious plugins. The vulnerability is exacerbated by the absence of client-side DOMPurify processing and crucial server-side security headers like Content-Security-Policy (CSP) on HTTP responses.

## Attack Chain

1. A malicious third-party package author crafts a `README.md` file containing an unsanitized HTML event handler (e.g., `onpointerover`) and a JavaScript payload designed to execute in the Administrator's browser.
2. The malicious package, including the crafted `README.md`, is submitted to and made available on the SiYuan Bazaar marketplace.
3. A SiYuan Administrator, with marketplace trust consent (`bazaar.trust`) enabled, navigates to "Settings → Marketplace" to browse community packages.
4. The SiYuan kernel fetches the package README for display via an API endpoint like `/api/bazaar/getBazaarPackageREADME` or `getInstalledPlugin`.
5. The `lute` rendering engine processes the Markdown README to HTML, but its `SetSanitize(true)` configuration, using an incomplete event handler blocklist, fails to remove the malicious `onpointerover` attribute and the embedded JavaScript.
6. The rendered HTML, now containing the active malicious JavaScript, is assigned to `mdElement.innerHTML` in the Administrator's browser within a plain DOM element, without any client-side DOMPurify or server-side security headers (CSP, X-Frame-Options) to mitigate XSS.
7. The Administrator interacts with the package listing in the UI, for example, by hovering their mouse pointer over the displayed README content.
8. The embedded JavaScript payload executes in the Administrator's authenticated SiYuan origin, leading to the theft of the kernel API token and granting the attacker full control over the workspace, including the ability to install further plugins.

## Impact

The successful exploitation of CVE-2026-54070 results in unauthenticated JavaScript execution within the Administrator's authenticated SiYuan origin upon viewing a specially crafted package README and one subsequent user interaction. This leads directly to the theft of the kernel API token (`conf.api.token`), which provides full administrative API access. With this token, attackers can achieve complete control over the SiYuan workspace, including installing malicious plugins, modifying data, or performing other unauthorized actions, effectively compromising the integrity and confidentiality of the entire SiYuan instance. A single malicious community package could compromise every instance whose administrator views its listing.

## Recommendation

* Apply the security patch for CVE-2026-54070 to SiYuan instances when it becomes available, specifically ensuring the `siyuan-note/siyuan` application is updated past version 3.6.5 and the `go/github.com/siyuan-note/siyuan/kernel` component is beyond version `0.0.0-20260628153353-2d5d72223df4`.
* Implement server-side HTTP security headers such as `Content-Security-Policy` (CSP), `X-Frame-Options`, and `X-Content-Type-Options` on the SiYuan kernel's HTTP responses to enhance client-side protection against XSS and similar attacks, as highlighted by the lack of these headers in the vulnerability analysis.
* Restrict Administrator access to the Bazaar marketplace or implement a stringent review process for third-party packages to prevent the introduction of malicious content.
* Monitor SiYuan API logs for unusual activity, particularly after administrators browse or interact with marketplace packages, looking for unauthorized `installBazaarPlugin` calls or unexpected API token usage.
