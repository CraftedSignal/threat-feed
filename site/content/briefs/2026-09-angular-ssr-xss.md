---
title: XSS Vulnerability in Angular Server-Side Rendering via Processing Instructions
slug: 2026-09-angular-ssr-xss
description: Angular platform-server is vulnerable to XSS when ProcessingInstruction nodes containing untrusted input are nested within fallback raw-content elements during server-side rendering.
date: "2026-09-28T22:15:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:angular:platform_server:*:*:*:*:*:*:*:*
tags:
  - xss
  - injection
  - web-application
  - server-side-rendering
  - angular
vendors:
  - Angular
products:
  - platform-server (>= 22.0.0, < 22.1.4)
  - platform-server (>= 21.0.0, < 21.2.22)
  - platform-server (>= 20.0.0, < 20.3.30)
  - platform-server (<= 19.2.25)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The renderer emits unescaped markup that causes the browser to parse and execute arbitrary JavaScript.
    confidence_band: high
cves:
  - id: CVE-2026-88058
    epss: 0.00875
references:
  - https://github.com/advisories/GHSA-j3r3-mxqp-r2p4
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88058
action_plan:
  priority: elevated
  owners:
    - Development
    - Security
  immediate_actions:
    - action: Upgrade platform-server to 20.3.30 or later
      owner: Development
      due: 72h
      evidence: Patched versions are documented in the GHSA release notes.
  mitigation_plan:
    - priority: immediate
      action: Review codebase for usages of createProcessingInstruction and sanitize input strings by encoding '<' characters.
      owner: Development
      addresses: CVE-2026-88058
      evidence: Workaround provided by Angular security guidance.
---

Angular's `@angular/platform-server` package contains an XSS vulnerability (CVE-2026-88058) affecting server-side rendering (SSR) serialization of DOM `ProcessingInstruction` nodes. When these nodes are nested inside fallback raw-content elements like `<noscript>`, `<iframe>`, `<noembed>`, or `<noframes>`, the serializer fails to properly escape the closing tags of ancestor containers (e.g., `</noscript>`) within the processing instruction data. 

In browsers, fallback raw-content elements cause the parser to enter `RAWTEXT` mode, where the parser looks for specific closing tag sequences to terminate the block. Because the Angular SSR serializer only escaped `>` and not `<`, an attacker providing a payload containing `</noscript ` within a `ProcessingInstruction` can cause the browser to prematurely close the container and treat sibling elements as active HTML. This allows for arbitrary JavaScript execution in the context of the user's session. The vulnerability affects multiple versions across Angular 19 through 22.

## Attack Chain

1. Application or library code programmatically calls `inject(DOCUMENT).createProcessingInstruction(target, data)` or uses `Renderer2` to insert nodes.
2. The application passes untrusted user input as the `data` parameter for the `ProcessingInstruction` node.
3. The node is inserted into a container that uses a fallback raw-content element (e.g., `<noscript>`).
4. The Angular server-side rendering engine serializes the DOM state to an HTML string.
5. The serializer fails to escape the `<` character in the processing instruction data, emitting `<?x </noscript ?>`.
6. The generated HTML string is sent to the client browser.
7. The client browser parses the HTML in `RAWTEXT` mode; the `</noscript` sequence terminates the `<noscript>` block.
8. Sibling markup elements following the breakout sequence are parsed as live HTML, executing injected malicious JavaScript.

## Impact

Successful exploitation allows for reflected or stored XSS depending on how the application handles input and rendering, leading to potential session hijacking, unauthorized actions on behalf of the user, or theft of sensitive data within the application. The reachability depends on the application's programmatic use of the `ProcessingInstruction` API with untrusted data, which is uncommon but possible in custom Angular library or component logic.

## Recommendation

* Upgrade to patched versions of `@angular/platform-server` (e.g., >= 22.1.4, >= 21.2.22, or >= 20.3.30) if available for your specific branch, or migrate to a secure version.
* Audit application code for usage of `document.createProcessingInstruction` or `Renderer2` DOM insertion methods, specifically looking for instances where user-supplied strings are passed to the `data` parameter.
* Implement strict input validation or manual escaping of the `<` character for any untrusted data destined for `ProcessingInstruction` nodes on the server until the software is patched.
