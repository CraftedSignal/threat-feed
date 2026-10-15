---
title: Reflected XSS in TanStack Start Server-Functions
slug: 2026-10-tanstack-xss
description: A critical reflected XSS vulnerability (CVE-2026-102989) in TanStack Start server-functions allows unauthenticated attackers to execute arbitrary JavaScript in the context of the application origin.
date: "2026-10-15T22:22:36Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:tanstack:start-server-core:*:*:*:*:*:*:*:*
  - cpe:2.3:a:tanstack:react-start:*:*:*:*:*:*:*:*
  - cpe:2.3:a:tanstack:solid-start:*:*:*:*:*:*:*:*
  - cpe:2.3:a:tanstack:vue-start:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - patch-now
vendors:
  - TanStack
products:
  - start-server-core (1.143.12 - <1.169.39)
  - react-start (1.143.12 - <1.168.60)
  - solid-start (1.143.12 - <1.168.57)
  - vue-start (1.143.12 - <1.168.56)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can craft a URL to a server function in an affected TanStack Start app.
    confidence_band: high
cves:
  - id: CVE-2026-102989
    cvss: 9.3
    epss: 0.00516
references:
  - https://github.com/advisories/GHSA-qx66-fv34-fjm8
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade TanStack Start packages to the identified fixed versions.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-102989 patch requirements.
  mitigation_plan:
    - priority: immediate
      action: 'Configure WAF to block server-function requests lacking ''x-tsr-serverFn: true'' header.'
      owner: Security Engineering
      addresses: CVE-2026-102989
      evidence: Source temporary mitigation guidance.
---

CVE-2026-102989 is a critical reflected cross-site scripting (XSS) vulnerability affecting TanStack Start framework applications. The issue stems from the server-function transport layer, which improperly allows request payload fields to influence internal middleware state rather than restricting input to defined public fields. An attacker can craft a malformed payload that forces an attacker-controlled result into the error path, which is then incorrectly processed by the response handler as an HTTP response. This allows the attacker to inject arbitrary HTML and execute JavaScript within the application's origin when a victim navigates to a crafted URL. Successful exploitation enables unauthorized access to same-origin data and the ability to perform requests on behalf of the victim.

## Attack Chain

1. Attacker identifies a target application utilizing vulnerable versions of TanStack Start.
2. Attacker crafts a malicious URL targeting a server-function endpoint, typically under the `/_serverFn/*` path.
3. Attacker injects a malicious payload into the request fields that influences internal middleware state.
4. The application receives the request and fails to validate the payload against expected public input fields.
5. The server-function error path processes the malformed payload, leading to the creation of a response-shaped object containing attacker-supplied content.
6. The server transmits the malicious response back to the client.
7. The victim's browser interprets the malicious response, executing the injected JavaScript in the context of the application's origin.

## Impact

The vulnerability allows unauthenticated attackers to perform reflected XSS attacks against any user who navigates to a crafted link. This provides the attacker the ability to steal sensitive user data, perform actions as the authenticated user, and bypass same-origin protections. All applications using affected versions of `@tanstack/start-server-core`, `@tanstack/react-start`, `@tanstack/solid-start`, and `@tanstack/vue-start` (version 1.143.12 and above) are exposed until patched.

## Recommendation

1. Upgrade all affected packages immediately to the following patched versions: `@tanstack/start-server-core@1.169.39`, `@tanstack/react-start@1.168.60`, `@tanstack/solid-start@1.168.57`, and `@tanstack/vue-start@1.168.56`.
2. Implement a restrictive Content Security Policy (CSP) to limit the execution of unauthorized scripts if patching is delayed.
3. Deploy WAF rules to block requests to `/_serverFn/*` that lack the mandatory `x-tsr-serverFn: true` header.
4. Configure WAF rules to block requests directed at server-function endpoints that contain headers associated with browser navigations, such as `Sec-Fetch-Mode: navigate` or `Accept: text/html`.
