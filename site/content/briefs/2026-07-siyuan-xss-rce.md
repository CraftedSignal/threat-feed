---
title: SiYuan Stored XSS Vulnerability Leading to RCE (CVE-2026-65605)
slug: 2026-07-siyuan-xss-rce
description: A stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-65605, exists in SiYuan prior to version v3.7.2. The flaw allows an attacker to inject crafted HTML, such as an `<img>` tag with an `onerror` attribute, which, when viewed in the Attribute View (database) cell rendering, executes arbitrary JavaScript and can escalate to remote code execution due to `nodeIntegration` being enabled in the desktop renderer.
date: "2026-07-23T12:27:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cross-site-scripting
  - xss
  - remote-code-execution
  - rce
  - vulnerability
  - electron
vendors:
  - SiYuan
products:
  - SiYuan < v3.7.2
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: a payload like <img src=x onerror=...> is stored unescaped and later inserted into the page via innerHTML, executing when the database is viewed.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Because the desktop renderer runs with nodeIntegration enabled, the injected script can reach require and escalate to arbitrary command execution.
    confidence_band: high
cves:
  - id: CVE-2026-65605
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65605
---

A critical stored cross-site scripting (XSS) vulnerability, tracked as CVE-2026-65605, has been identified in SiYuan versions prior to v3.7.2. This flaw resides in the "Attribute View" (database) cell rendering, where "Template" column values are rendered as HTML. The application's sanitization mechanism fails to properly auto-escape all HTML, specifically when balanced self-closing tags like `<img>` are present. An attacker can inject a payload such as `<img src=x onerror=...>` into a Template column. When a user views the affected database, the malicious payload is rendered unescaped via `innerHTML`, leading to JavaScript execution. Critically, because the SiYuan desktop renderer operates with `nodeIntegration` enabled, the injected JavaScript can access Node.js APIs, allowing it to leverage `require` for arbitrary command execution on the victim's underlying operating system. This vulnerability poses a significant risk of remote code execution.

## Attack Chain

1. An attacker crafts a malicious payload containing JavaScript, such as `<img src=x onerror='require("child_process").exec("calc.exe")'>`.
2. The attacker inserts this payload into a "Template" column value within the "Attribute View" of a SiYuan database entry.
3. The SiYuan application stores this malicious payload unescaped because its `HasUnclosedHtmlTag` check skips balanced self-closing tags, circumventing proper HTML escaping.
4. A legitimate user accesses or views the database entry containing the maliciously crafted input within the SiYuan application.
5. The SiYuan desktop renderer processes and renders the database cell content, inserting the stored malicious HTML payload directly into the page's Document Object Model (DOM) via `innerHTML`.
6. The embedded JavaScript code (e.g., within the `onerror` attribute of the `<img>` tag) executes within the context of the SiYuan application.
7. Due to `nodeIntegration` being enabled in the desktop renderer, the executed JavaScript gains access to Node.js APIs, including the `require` function.
8. The script leverages `require` to load Node.js modules (e.g., `child_process`) and execute arbitrary commands on the victim's underlying operating system, achieving remote code execution.

## Impact

Successful exploitation of CVE-2026-65605 results in arbitrary code execution on the victim's operating system with the privileges of the SiYuan desktop application. This can lead to complete compromise of the affected system, including data theft, installation of additional malware, or further network lateral movement. The vulnerability's CVSS v3.1 Base Score is 9.6, indicating critical severity. All users running SiYuan desktop applications prior to version v3.7.2 are at risk.

## Recommendation

* Patch CVE-2026-65605 by updating all SiYuan installations to version v3.7.2 or later immediately.
* Implement strong egress filtering to prevent unauthorized outbound connections initiated by potentially compromised applications.
