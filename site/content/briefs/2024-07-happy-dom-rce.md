---
brief_id: brief-2024-07-03-happy-dom-rce
event_id: brief-2024-07-03-happy-dom-rce
revision: 1
activity_at: "2024-07-03T14:00:00Z"
title: Happy DOM ECMAScriptModuleCompiler Remote Code Execution
slug: 2024-07-happy-dom-rce
description: A code injection vulnerability exists in Happy DOM's ECMAScriptModuleCompiler, allowing remote code execution (RCE) by injecting arbitrary JavaScript expressions into `export { }` declarations, enabling command execution if JavaScript evaluation is enabled.
date: "2024-07-03T14:00:00Z"
lastmod: "2026-10-24T03:46:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:capricorn86:happy_dom:*:*:*:*:*:node.js:*:*
has_poc: true
tags:
  - happy-dom
  - rce
  - code-injection
  - javascript
vendors:
  - Happy DOM
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2024-51757
    epss: 0.00772
    kev_status: "false"
  - id: CVE-2025-61927
    epss: 0.00642
    kev_status: "false"
  - id: CVE-2026-33943
    cvss: 8.8
    epss: 0.0097
    kev_status: "false"
  - id: CVE-2026-115895
    cvss: 8.8
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-6q6h-j7hj-3r64
  - https://github.com/advisories/GHSA-834v-8h66-3h79
rules:
  - title: Detect Happy DOM RCE via export injection
    description: Detects potential RCE attempts in Happy DOM by monitoring for process creation events where 'child_process' is involved, indicating command execution via the vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Happy DOM RCE via web request
    description: Detects potential RCE attempts in Happy DOM by monitoring for suspicious web requests containing <script type='module'> tags with javascript code within the export statement.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-10-24T03:46:00Z"
    level: L2
    summary: poc_available; added CVE-2024-51757 +3
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-834v-8h66-3h79
---

Happy DOM, a browser automation library, is susceptible to a code injection vulnerability within its `ECMAScriptModuleCompiler`. This flaw allows attackers to inject arbitrary JavaScript expressions into `export { }` declarations in ES module scripts. Specifically, the compiler directly interpolates unsanitized content into generated code as an executable expression. The inadequate sanitization, which fails to strip backticks, enables the use of template literals to bypass security measures. This vulnerability is present in versions 15.10.0 through 20.8.7 and can be exploited when JavaScript evaluation is explicitly enabled. This issue differs from CVE-2024-51757 and CVE-2025-61927, which were patched in earlier versions. Defenders should be aware of the risk, particularly in environments where happy-dom processes untrusted HTML content.

## Attack Chain

1.  The attacker injects malicious JavaScript code within an HTML `<script type="module">` tag intended for processing by happy-dom. The payload is crafted within an `export { ... }` declaration. For example: `export { require(`child_process`).execSync(`id`) }`.
2.  Happy DOM's `ECMAScriptModuleCompiler.ts` processes the HTML, extracting the content within the `export { ... }` declaration using a regular expression that is overly permissive.
3.  The extracted content, `require(\`child_process\`).execSync(\`id\`)`, is passed through a flawed sanitization function that removes single and double quotes but fails to remove backticks.
4.  The unsanitized content is then directly interpolated into the generated JavaScript code as an executable expression: `$happy_dom.exports['${exportName}'] = ${importName}`.
5.  The generated JavaScript code, now containing the injected malicious command, is evaluated by happy-dom's scripting engine.
6.  The `child_process.execSync` function executes the injected command (`id` in this example) on the host system.
7.  The output of the command is captured and potentially used for further exploitation or data exfiltration.
8.  The attacker achieves Remote Code Execution (RCE) on the host system, gaining the ability to execute arbitrary commands.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve remote code execution (RCE) on systems using happy-dom to process HTML with JavaScript evaluation enabled. This can lead to complete system compromise, data theft, or denial of service. The vulnerability affects applications using happy-dom for server-side rendering (SSR) of user-supplied HTML, web scraping of untrusted content, and testing pipelines that load untrusted HTML fixtures. Given the wide use of JavaScript-based tools and frameworks, the impact can be significant for vulnerable systems where JavaScript evaluation is enabled.

## Recommendation

*   Upgrade to a patched version of happy-dom that addresses CVE-2026-33943 once available.
*   Disable JavaScript evaluation in happy-dom if it is not required for your application to mitigate CVE-2026-33943.
*   Implement strict input validation and sanitization of any HTML content processed by happy-dom, ensuring that `export { ... }` declarations do not contain potentially malicious JavaScript code.
*   Deploy the Sigma rule `Detect Happy DOM RCE via export injection` to detect exploitation attempts based on process creation with the `child_process` module.
*   Monitor web server logs for suspicious requests containing JavaScript code within `<script type="module">` tags that could be used to inject malicious payloads (see `Detect Happy DOM RCE via web request` Sigma rule).
*   Enable Sysmon process creation logging to enhance visibility into spawned processes and detect potential command execution resulting from this vulnerability.
