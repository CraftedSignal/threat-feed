---
title: Stored/Reflected XSS in Quasar Framework SSR via Unescaped Meta Tag Rendering
slug: 2026-10-quasar-xss
description: The Quasar Framework's server-side rendering (SSR) mechanism in versions prior to 2.22.0 fails to escape HTML characters in meta tags, allowing attackers to inject and execute arbitrary JavaScript in the victim's browser.
date: "2026-10-07T16:56:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:quasar-framework:quasar:*:*:*:*:*:*:*:*
vendors:
  - Quasar
products:
  - Quasar Framework (< 2.22.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who can influence that underlying text sets it to a payload that breaks out of its intended HTML context.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The injected <script> executes immediately, before hydration, with full access to document.cookie and the DOM.
    confidence_band: high
cves:
  - id: CVE-2026-106102
    cvss: 10
references:
  - https://github.com/advisories/GHSA-pq96-jpmf-w254
action_plan:
  priority: immediate_escalation
  owners:
    - Development
    - Security Operations
  immediate_actions:
    - action: Upgrade Quasar Framework to version 2.22.0 or later
      owner: Development
      due: 24h
      evidence: Source states Quasar < 2.22.0 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Upgrade Quasar Framework to 2.22.0 or later
      owner: IT Operations
      addresses: CVE-2026-106102
      evidence: Quasar Framework < 2.22.0
---

Quasar Framework versions prior to 2.22.0 contain a critical vulnerability in the server-side rendering (SSR) utility `getHead()`, located in `ui/src/plugins/meta/Meta.js`. This function is responsible for serializing metadata - such as page titles, meta descriptions, and link tags - collected via the `useMeta()` composable into raw HTML for initial server-side rendering.

The vulnerability exists because `getHead()` uses insecure template-literal interpolation to construct HTML strings without any HTML-entity or attribute-quote escaping. In contrast, the client-side `apply()` method uses safe DOM APIs (`document.createElement` and `setAttribute`) that handle escaping automatically. Because `getHead()` is a parallel, independent implementation for the SSR path, it remains vulnerable. An attacker can input strings containing HTML metacharacters (e.g., `</title>`, `"`, `>`) through any application input that eventually populates `useMeta()`, resulting in the injection of arbitrary malicious markup, including `<script>` tags, into the server-rendered HTML response.

## Attack Chain

1. Attacker identifies an application input field (e.g., blog post title, user display name, or CMS field) that is processed and rendered by the Quasar SSR `useMeta()` composable.
2. Attacker submits a payload containing malicious HTML characters, such as `My Post</title><script>alert(document.cookie)</script>`.
3. The application backend stores this malicious string in the database or passes it to the SSR rendering pipeline.
4. A victim requests the page, triggering the Quasar SSR `getHead()` utility on the server.
5. The `getHead()` function serializes the malicious payload into the raw HTML `<head>` segment without escaping characters.
6. The server sends the unsanitized HTML response to the victim's browser.
7. The browser parses the injected `<script>` tag before hydration, executing the attacker-supplied JavaScript in the context of the site origin.
8. The script performs malicious actions such as exfiltrating `document.cookie` or overlaying phishing content.

## Impact

Successful exploitation allows for reflected or stored Cross-Site Scripting (XSS). This gives the attacker the ability to steal user session cookies, perform unauthorized actions on behalf of the user, modify the page content, or redirect users to malicious domains. The vulnerability is highly impactful because `useMeta()` is a primary and common component used in almost all dynamic Quasar SSR applications, making a wide range of content-heavy sites potentially susceptible to trivial exploitation.

## Recommendation

Prioritized actions for development and security engineering teams:
- Update the Quasar Framework to version 2.22.0 or later immediately to patch CVE-2026-106102.
- Audit existing SSR implementations for `useMeta()` usage where user-controlled input might be processed and rendered server-side.
- Implement a rigorous server-side HTML-escaping routine for all metadata attributes if an immediate framework update is not possible.
