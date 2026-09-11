---
title: Cross-Site Scripting in Angular Platform Server SSR
slug: 2026-09-angular-ssr-xss
description: An XSS vulnerability in Angular's server-side rendering serializer fails to escape closing tags within <template> content nested inside fallback raw-content elements, allowing arbitrary script execution.
date: "2026-09-11T00:55:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:google:angular:*:*:*:*:*:*:*:*
vendors:
  - Google
products:
  - Angular platform-server (>= 22.0.0, < 22.1.4)
  - Angular platform-server (>= 21.0.0, < 21.2.22)
  - Angular platform-server (>= 20.0.0, < 20.3.30)
  - Angular platform-server (<= 19.2.25)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: The serializer's failure to escape tags within SSR output allows for the execution of arbitrary injected markup in the user browser.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: JavaScript
    evidence: The injected payload prematurely terminates the fallback container and executes trailing markup as active DOM elements.
    confidence_band: high
cves:
  - id: CVE-2026-88060
references:
  - https://github.com/advisories/GHSA-v3p8-whq6-r5jg
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-88060
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade @angular/platform-server to patched versions (22.1.4, 21.2.22, 20.3.30, or 19.2.26+).
      owner: IT Operations
      due: 48h
      evidence: Source provided specific patched version ranges for each affected major release.
  mitigation_plan:
    - priority: immediate
      action: Identify and sanitize all untrusted inputs rendered inside <noscript>, <iframe>, <noembed>, or <noframes> containers using <template>.
      owner: Application Security
      addresses: CVE-2026-88060
      evidence: Source provided guidance on avoiding problematic template structures.
---

A high-severity Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-88060, affects the `@angular/platform-server` package used for server-side rendering (SSR). The flaw occurs because the HTML serializer fails to correctly identify and escape closing tags when processing `<template>` content that resides within fallback raw-content elements, such as `<noscript>`, `<iframe>`, `<noembed>`, or `<noframes>`. 

In HTML5, these elements place the browser in `RAWTEXT` mode, where internal content is parsed as literal text until a matching closing tag is encountered. Because Angular's serializer treats the contents of a `<template>` as a separate `DocumentFragment` with a null parent, the traversal logic fails to detect the outer fallback raw-content container. Consequently, malicious input containing closing tags is rendered unescaped in the SSR output, leading to a container breakout and subsequent execution of injected markup when the page is parsed by a victim's browser. This bypasses Angular's built-in protections for standard text interpolation.

## Impact

Successful exploitation allows for the execution of arbitrary JavaScript within the context of the user's session, potentially leading to session hijacking, data exfiltration, or unauthorized actions on behalf of the user. The vulnerability is reachable through both standard text interpolation and imperative DOM construction via `Renderer2`. Affected versions include `@angular/platform-server` v19.2.25 and below, 20.0.0 through 20.3.29, 21.0.0 through 21.2.21, and 22.0.0 through 22.1.3. Organizations utilizing Angular SSR with dynamic, user-controllable input rendered within the specified template containers are at risk.

## Recommendation

Prioritized remediation involves updating the `@angular/platform-server` package to the latest patched releases. If immediate patching is not feasible, restrict the use of untrusted user input within `<template>` elements nested in `<noscript>`, `<iframe>`, `<noembed>`, or `<noframes>`. Security teams should audit codebases for components that use `Renderer2` to dynamically construct DOM structures involving these fallback elements to ensure input is sanitized before rendering.
