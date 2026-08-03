---
title: Cross-Site Scripting Vulnerability in Angular Server-Side Rendering
slug: 2026-08-angular-ssr-xss
description: A Cross-Site Scripting (XSS) vulnerability in @angular/platform-server (CVE-2026-69149) allows script injection via improper serialization of fallback raw-content elements during server-side rendering.
date: "2026-08-03T17:59:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - angular
vendors:
  - Angular
products:
  - platform-server (19)
  - platform-server (20)
  - platform-server (21)
  - platform-server (22)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: This vulnerability allows an attacker to perform same-origin Cross-Site Scripting (XSS) attacks against any user visiting an SSR-rendered page.
    confidence_band: high
cves:
  - id: CVE-2026-69149
references:
  - https://github.com/advisories/GHSA-vpx6-8pjr-4g3v
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-69149
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Update @angular/platform-server to versions 22.0.7, 21.2.19, or 20.3.27
      owner: IT Operations
      due: 48h
      evidence: Patched version list provided by GitHub Advisory GHSA-vpx6-8pjr-4g3v
  mitigation_plan:
    - priority: immediate
      action: Disable inlineCritical in angular.json or render options
      owner: Application Security
      addresses: CVE-2026-69149
      evidence: Workaround documentation provided in advisory
---

A Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-69149, affects the `@angular/platform-server` package, specifically within its integration with the `domino` DOM emulation library. The issue stems from the improper serialization of fallback raw-content elements, including `<iframe>`, `<noembed>`, `<noframes>`, and `<noscript>`. When dynamic user-controlled text is bound within these elements, the serializer fails to escape closing tags. During Server-Side Rendering (SSR) post-processing, the unescaped closing tags are rendered into the final HTML output. When a browser subsequently parses this HTML, the injected closing tag causes the browser to terminate the element prematurely, allowing an attacker to inject and execute arbitrary JavaScript within the user's session context. This vulnerability impacts multiple versions of Angular, including those in the 19, 20, 21, and 22 release lines.

## Impact

Successful exploitation allows for same-origin XSS attacks against users visiting SSR-rendered applications. Potential impacts include session hijacking, theft of sensitive credentials, unauthorized performative actions on behalf of the user, and website defacement. Organizations using SSR with user-supplied data input in the specified elements are at high risk.

## Recommendation

* Update `@angular/platform-server` to the patched versions: 22.0.7, 21.2.19, or 20.3.27, depending on the active release stream.
* If patching is not immediately feasible, disable `inlineCritical` style optimization in `angular.json` or within `CommonEngine` render options to prevent the vulnerable `domino` re-serialization process.
* Implement strict input sanitization to strip or escape closing tags from any user-controlled data intended for placement inside `<iframe>`, `<noembed>`, `<noframes>`, or `<noscript>` elements.
* Audit codebase for bindings that place user-supplied content inside these specific raw-content tags.
