---
title: SVGO removeScripts Plugin XSS Bypass
slug: 2026-09-svgo-xss-bypass
description: The SVGO 'removeScripts' plugin is vulnerable to XSS bypasses due to insufficient validation of namespace-prefixed SVG anchors and control-character obfuscation in URL schemes, potentially allowing script execution when untrusted SVG content is rendered.
date: "2026-09-08T21:50:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:svgo_project:svgo:*:*:*:*:*:node.js:*:*
tags:
  - xss
  - svg
  - sanitization-bypass
  - cve-2026-84370
vendors:
  - SVGO
products:
  - svgo (2.x < 2.8.4)
  - svgo (3.x < 3.3.5)
  - svgo (4.x < 4.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Applications that used this plugin as their only protection for untrusted SVG input could expose users to cross-site scripting (XSS).
    confidence_band: high
cves:
  - id: CVE-2026-84370
    cvss: 8.2
    epss: 0.00336
references:
  - https://github.com/advisories/GHSA-w27v-7q3p-w38r
  - https://github.com/svg/svgo/pull/2268
  - https://github.com/svg/svgo/releases/tag/v4.1.0
action_plan:
  priority: elevated
  owners:
    - Development
    - Security Operations
  immediate_actions:
    - action: Audit applications utilizing the svgo 'removeScripts' plugin to process untrusted user input.
      owner: Security Operations
      due: 48h
      evidence: The plugin is opt-in, so consumers that do not enable it are not relying on the affected behavior.
    - action: 'Upgrade svgo dependencies to the appropriate patched versions: 2.8.4, 3.3.5, or 4.1.0.'
      owner: Development
      due: 72h
      evidence: Upgrade to one of the following releases for the maintained release line in use.
  mitigation_plan:
    - priority: immediate
      action: Integrate a robust SVG sanitizer (e.g., DOMPurify) before SVGO processing for untrusted input.
      owner: Development
      addresses: CVE-2026-84370
      evidence: For hostile input, use a dedicated SVG sanitization tool before passing the SVG to SVGO.
---

SVGO (SVG Optimizer) contains a security flaw in its `removeScripts` plugin, identified as CVE-2026-84370. The plugin, intended to strip executable script elements and links from SVG files, fails to adequately neutralize malicious payloads due to two specific bypass mechanisms. First, the plugin only validates unprefixed `<a>` tags and ignores namespace-prefixed anchors (e.g., `<svg:a>`), allowing executable links to persist. Second, the URL scheme validator does not sanitize embedded ASCII control characters such as tabs, line feeds, or carriage returns. Browsers ignore these characters during URI parsing, effectively allowing attackers to obfuscate `javascript:` URI schemes (e.g., `java&#9;script:`) to bypass the plugin's pattern matching.

This vulnerability affects versions of the `svgo` npm package across major release lines. Users relying on this plugin as the sole sanitization mechanism for untrusted user-provided SVG files are at risk of cross-site scripting (XSS) if the optimized output is rendered in an active browser context.

## Impact

Successful exploitation occurs when an application processes untrusted, attacker-controlled SVG files using the vulnerable `removeScripts` plugin and subsequently renders these files in a victim's browser session. By leveraging these bypasses, an attacker can execute arbitrary JavaScript within the context of the affected application's origin. This can lead to session hijacking via cookie theft, unauthorized actions performed on behalf of the user, or manipulation of the application's DOM. The severity is heightened for applications that serve user-uploaded SVGs in same-origin contexts.

## Recommendation

1. Patch immediately by upgrading to the designated fixed versions: upgrade v2 users to 2.8.4, v3 users to 3.3.5, and v4 users to 4.1.0.
2. For applications handling hostile or untrusted SVG input, implement a dedicated SVG sanitization library (such as DOMPurify) as a pre-processing step before passing input to SVGO.
3. Where possible, serve user-controlled SVG files in a sandboxed, cross-origin context (e.g., using a dedicated domain or Content-Security-Policy headers) to minimize the impact of potential XSS.
