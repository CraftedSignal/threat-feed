---
title: Quasar Framework SSR/SSG Development Server Information Disclosure and HTML Injection
slug: 2026-10-quasar-ssr-disclosure
description: The Quasar Framework development server exposes environment variables, cookies, and request headers via an unauthenticated error page that is also susceptible to HTML injection due to an incomplete sanitization routine.
date: "2026-10-07T16:59:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:quasar:render-ssr-error:*:*:*:*:*:*:*:*
  - cpe:2.3:a:quasar:app-vite:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cve
  - web-application
  - quasar
vendors:
  - Quasar
products:
  - '@quasar/render-ssr-error (<= 2.2.3)'
  - '@quasar/app-vite (<= 3.2.0)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Quasar Framework development server improperly exposes sensitive environment variables... via an unauthenticated error page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The error page contains an HTML injection vulnerability... allowing an attacker to execute arbitrary JavaScript.
    confidence_band: high
cves:
  - id: CVE-2026-106106
references:
  - https://github.com/advisories/GHSA-r5mf-4r5x-q78f
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Audit all internal development environments running Quasar for exposure on non-localhost interfaces.
      owner: Security Operations
      due: 24h
      evidence: Quasar dev server defaults to binding to 0.0.0.0, exposing this information to any host.
  mitigation_plan:
    - priority: immediate
      action: Upgrade @quasar/render-ssr-error and @quasar/app-vite to patched versions.
      owner: IT Operations
      addresses: CVE-2026-106106
      evidence: 'Affected packages: @quasar/render-ssr-error (<= 2.2.3), @quasar/app-vite (<= 3.2.0)'
---

The Quasar Framework development server, used in SSR and SSG modes, contains a critical information disclosure vulnerability (CVE-2026-106106) in the `renderSSRError` utility. When a rendering exception occurs during development, the framework serializes sensitive data including the full shell environment (`process.env`), all request headers, and all cookies into an HTTP 500 error page. Because the Quasar CLI overrides the Vite default `localhost` binding to listen on `0.0.0.0`, this sensitive information is exposed to any network host capable of reaching the development port.

Furthermore, the error page embeds this serialized data within a `<script>` element using a flawed string replacement routine (`replaceAll('</script>', ...)`). This filter is ASCII-case-sensitive and fails to identify variations such as `</SCRIPT>`, `</script >`, or `</script/>`, allowing an attacker to escape the script context and execute arbitrary JavaScript in the origin of the development server. This issue affects `@quasar/render-ssr-error` versions 2.2.3 and below, and `@quasar/app-vite` versions 3.2.0 and below.

## Attack Chain

1. The attacker scans the network for development servers listening on Quasar's default ports or configured ports that are exposed via the `0.0.0.0` binding.
2. The attacker triggers a server-side rendering (SSR) or static site generation (SSG) error by sending a malformed request that causes the application logic to throw an exception.
3. The Quasar development server invokes `renderSSRError`, which collects the server's environment variables (including cloud credentials, tokens, and database strings) and request metadata.
4. The framework serializes this information into a 500 error response page.
5. The attacker retrieves the full environment dump via an unauthenticated GET request.
6. To achieve code execution, the attacker provides a malicious payload in an HTTP header or a cookie that, when processed by the disclosure page, breaks out of the script tag using an unescaped tag like `</SCRIPT >`.
7. The developer's browser renders the malicious script, allowing the attacker to execute code in the local dev environment context.

## Impact

Successful exploitation allows for the unauthorized exfiltration of highly sensitive development credentials, including AWS secret keys, GitHub or NPM registry tokens, and database connection strings. By chaining the information disclosure with the HTML injection vulnerability, an attacker can also gain JavaScript execution within the developer's browser, potentially leading to session hijacking or local file interactions. This represents a significant risk for any organization utilizing Quasar in a networked development environment.

## Recommendation

1. Upgrade affected projects to versions of `@quasar/render-ssr-error` and `@quasar/app-vite` that include the patch for CVE-2026-106106.
2. Ensure the development server is configured to bind to `127.0.0.1` rather than `0.0.0.0` to restrict access to the local machine.
3. Implement strict network segmentation for development environments to prevent unauthorized network access to local development ports.
4. Audit local development environments for potential credential leakage if the vulnerable version was previously exposed to any untrusted network segments.
