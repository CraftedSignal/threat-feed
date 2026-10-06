---
title: Stored XSS in @vue/server-renderer via Attribute Name Injection
slug: 2026-10-vue-ssr-xss
description: An insufficient character blacklist in @vue/server-renderer allows attackers to inject arbitrary HTML attributes by including carriage return characters in dynamic binding keys.
date: "2026-10-06T00:46:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-application
  - vue
  - ssr
  - code-vulnerability
vendors:
  - Vue
products:
  - '@vue/server-renderer (<= 3.5.41)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The browser interprets the injected attributes to execute attacker-controlled JavaScript payloads automatically upon page load.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-g2v6-rqmx-r4w6
action_plan:
  priority: elevated
  owners:
    - Application Security
    - Development
  immediate_actions:
    - action: Audit application source code for usage of v-bind on objects derived from untrusted user input.
      owner: Development
      due: 48h
      evidence: Source document describes the vulnerability occurring specifically when keys are derived from external data.
  mitigation_plan:
    - priority: immediate
      action: Upgrade @vue/server-renderer to a version that includes the fix for carriage return filtering.
      owner: Development
      addresses: XSS vulnerability in server-side attribute rendering
      evidence: Source identifies the lack of CR filtering as the root cause.
---

The `@vue/server-renderer` package (version 3.5.41 and earlier) contains a vulnerability in its server-side rendering (SSR) logic that permits stored Cross-Site Scripting (XSS). The function `ssrRenderDynamicAttr`, which handles dynamic attributes bound via `v-bind`, relies on an attribute name validation utility (`isSSRSafeAttrName`) to sanitize keys. This utility utilizes a blacklist that fails to include the carriage return character (U+000D). 

Because web browsers perform HTML input stream preprocessing - converting carriage returns not followed by line feeds into line feeds - an attacker who can influence the keys in a bound object can supply a string containing `\r`. This character terminates the intended attribute name and allows for the injection of new, arbitrary attributes (e.g., `autofocus` or `onfocus`) into the rendered HTML output. Since this occurs during the server-side rendering phase, the resulting XSS payload is served directly to users, leading to full script execution in the context of the victim's session without requiring user interaction.

## Attack Chain

1. Attacker identifies a feature in a web application that renders user-controllable object keys using Vue SSR (e.g., dynamic attribute configuration in a CMS or form builder).
2. Attacker crafts a malicious input string containing carriage returns (e.g., `x\rautofocus\ronfocus`) to be used as a key in a dynamic attribute object.
3. The application passes the malicious object to `v-bind` or the internal `ssrRenderAttrs()` function during server-side rendering.
4. The `isSSRSafeAttrName` utility validates the key against its blacklist; since `\r` is not blocked, it marks the key as safe.
5. The server-side code generates an HTML string where the `\r` remains embedded in the attribute name (e.g., `<div x\rautofocus\ronfocus="...">`).
6. The server sends this generated HTML to the victim's browser.
7. The browser performs HTML input stream normalization, interpreting the `\r` characters as delimiters, effectively creating new attributes like `autofocus` and `onfocus`.
8. The browser executes the injected JavaScript code (e.g., `alert(document.cookie)`) upon page load.

## Impact

Successful exploitation results in full stored XSS within the target application. This allows attackers to execute arbitrary JavaScript in the context of any user viewing the affected page, leading to session hijacking, unauthorized data exfiltration, and potential complete account takeover. The vulnerability is highly severe in SSR contexts where dynamic object binding is used to construct HTML elements from untrusted inputs, such as in administrative dashboards or user-facing portals supporting custom configurations.

## Recommendation

Prioritize the following actions for your development and security teams:
- Upgrade `@vue/server-renderer` to a patched version that explicitly blacklists carriage return (U+000D) characters in `isSSRSafeAttrName`.
- Perform a code audit of all SSR-enabled Vue components to identify instances where `v-bind` or `ssrRenderAttrs` processes objects with keys derived from external data.
- Implement strict allowlists for dynamic attribute names where user input is involved, rather than relying solely on blacklisting unsafe characters.
