---
title: SiYuan Bazaar Marketplace Stored XSS Leads to Electron RCE
slug: 2026-05-siyuan-bazaar-xss
description: SiYuan's Bazaar marketplace is vulnerable to stored cross-site scripting (XSS) via unescaped package metadata, leading to arbitrary OS command execution in the desktop Electron client.
date: "2026-05-13T15:35:14Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - xss
  - rce
  - electron
  - siyuan
vendors:
  - GitHub
products:
  - github.com/siyuan-note/siyuan/kernel (<= 0.0.0-20260421031503-96dfe0bea474)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1055
    technique_name: Process Injection
references:
  - https://github.com/advisories/GHSA-27qc-m5gf-jv5r
rules:
  - title: Detect SiYuan Bazaar XSS via Malicious Plugin Name
    description: Detects CVE-2026-45375 exploitation — XSS attempt via malicious img tag in SiYuan Bazaar plugin name field
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1055
    data_sources:
      - process_creation
      - windows
  - title: Detect SiYuan Bazaar XSS via Malicious Plugin Version
    description: Detects CVE-2026-45375 exploitation — XSS attempt via malicious img tag in SiYuan Bazaar plugin version field
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1055
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

SiYuan's Bazaar (community marketplace) renders the `name` and `version` fields of a package's `plugin.json` into the Settings → Marketplace UI without HTML escaping, leading to a stored XSS vulnerability. The kernel-side helper `sanitizePackageDisplayStrings` in `kernel/bazaar/package.go` HTML-escapes only `Author`, `DisplayName`, and `Description` — `Name` and `Version` flow through to the renderer raw. Because the desktop client is built on Electron with `nodeIntegration: true`, `contextIsolation: false`, and `webSecurity: false`, the resulting cross-site scripting executes in a renderer with full access to Node.js APIs, escalating directly to arbitrary OS command execution under the victim's account. The trigger requires merely opening Settings → Marketplace → Downloaded → Plugins. This vulnerability affects SiYuan kernel versions up to and including `0.0.0-20260421031503-96dfe0bea474`.

## Attack Chain

1. An attacker crafts a malicious plugin manifest (`plugin.json`) containing a payload in the `name` or `version` fields, such as `<img src=x onerror="require('child_process').exec('...')">`.
2. The attacker submits the malicious plugin manifest to the SiYuan Bazaar marketplace, or places it in the local plugins directory.
3. The SiYuan kernel retrieves and stores the plugin manifest without properly sanitizing the `name` and `version` fields.
4. A user opens the SiYuan application and navigates to Settings → Marketplace → Downloaded → Plugins.
5. The SiYuan frontend fetches the plugin metadata, including the unsanitized `name` and `version` fields, from the backend.
6. The frontend substitutes the `name` or `version` fields into the HTML of the marketplace card list via `${item.preferredName}`, `${data.name}`, or `v${data.version}`.
7. The browser parses the malicious HTML, triggering the `onerror` event of the injected `<img>` tag.
8. The `onerror` handler executes `require('child_process').exec(...)`, leading to arbitrary OS command execution under the user's account.

## Impact

Successful exploitation results in arbitrary OS command execution on the victim's machine with the privileges of the user running the SiYuan application. This allows attackers to steal sensitive information, install malware, or perform other malicious actions. The vulnerability is triggered by simply viewing the marketplace listing, making it a zero-click exploit. The injected payload is visually undetectable due to the use of `display:none` style, making the attack stealthy. The Bazaar marketplace serves as a low-friction delivery channel.

## Recommendation

*   Deploy the Sigma rule `Detect SiYuan Bazaar XSS via Malicious Plugin Name` to detect exploitation attempts by monitoring for img tags with onerror attributes in bazaar package names.
*   Deploy the Sigma rule `Detect SiYuan Bazaar XSS via Malicious Plugin Version` to detect exploitation attempts by monitoring for img tags with onerror attributes in bazaar package versions.
*   Upgrade to a patched version of SiYuan that includes proper HTML escaping of package metadata to address CVE-2026-45375.
*   Implement the suggested fix by extending the kernel allowlist in `kernel/bazaar/package.go` to escape the `Name`, `Version`, and `Keywords` fields.
*   Apply the secondary fix by calling `sanitizePackageDisplayStrings` from `kernel/bazaar/bazaar.go:48` to ensure consistent sanitization.
*   Harden the Electron renderer by enabling `contextIsolation: true` in `app/electron/main.js` to limit the impact of future XSS vulnerabilities.
