---
title: Quasar Framework App Vite SSR and SSG Nonce Attribute Injection
slug: 2026-10-quasar-app-vite-nonce-injection
description: The @quasar/app-vite package (<= 3.2.0) is vulnerable to attribute injection in SSR and SSG renderer paths where unsanitized nonce values can be used to inject arbitrary HTML attributes.
date: "2026-10-07T16:59:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:quasar:app_vite:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - injection
  - app-vite
  - quasar
  - cve-2026-106107
vendors:
  - Quasar
products:
  - app-vite (<= 3.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Several @quasar/app-vite SSR and SSG renderer paths interpolate ssrContext.nonce directly into quoted HTML attributes.
    confidence_band: high
cves:
  - id: CVE-2026-106107
references:
  - https://github.com/advisories/GHSA-5m6h-8g35-p3m7
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-106107
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade app-vite to 3.3.0 or later
      owner: IT Operations
      addresses: CVE-2026-106107
      evidence: Remediation centralizes nonce handling and validates the value as a non-empty base64/base64url CSP nonce.
---

The Quasar Framework package @quasar/app-vite is susceptible to an attribute injection vulnerability (CVE-2026-106107) within its server-side rendering (SSR) and static site generation (SSG) processes. The vulnerability exists because the `ssrContext.nonce` variable is interpolated directly into HTML attributes without adequate validation or sanitization. If a web application utilizing this framework allows untrusted user-supplied data to influence or override the `ssrContext.nonce` field, an attacker can provide a string containing quote characters (e.g., `"` or `'`) to terminate the attribute prematurely and inject additional malicious HTML attributes or markup. While cryptographically standard base64/base64url nonces are inherently safe, the lack of programmatic constraints on this input field enables potential cross-site scripting (XSS) or DOM-based injection scenarios in misconfigured applications.

## Impact

Successful exploitation of this vulnerability allows an attacker to inject arbitrary HTML attributes or elements into the rendered output of a Quasar application. Depending on the application's implementation and the injected content, this could lead to the execution of unauthorized JavaScript, manipulation of DOM structure, or the bypass of Content Security Policy (CSP) protections if the nonce mechanism is compromised. The vulnerability affects all versions of @quasar/app-vite up to and including 3.2.0.

## Recommendation

* Update @quasar/app-vite to the latest version that implements centralized nonce handling, which enforces strict base64/base64url validation and HTML encoding of the nonce attribute.
* Audit existing applications using the Quasar framework to ensure that no untrusted user input is being passed into `ssrContext.nonce` within the server-side rendering configuration.
* Implement a robust Content Security Policy (CSP) that does not rely solely on dynamically generated nonces from potentially unsafe inputs if the application architecture cannot guarantee input sanitization.
