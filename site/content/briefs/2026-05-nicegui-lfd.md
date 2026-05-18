---
title: NiceGUI Local File Disclosure via Docutils File Insertion (CVE-2026-45553)
slug: 2026-05-nicegui-lfd
description: CVE-2026-45553 allows a remote attacker to read arbitrary local files by injecting reStructuredText directives into the `ui.restructured_text()` function of a NiceGUI application, if the application passes user-controlled content to that function.
date: "2026-05-18T20:22:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - local-file-disclosure
  - nicegui
  - docutils
  - CVE-2026-45553
vendors:
  - pip
products:
  - nicegui (<= 3.11.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-jfrm-rx66-g536
rules:
  - title: Detect NiceGUI RCE Attempts via Restructured Text
    description: Detects CVE-2026-45553 exploitation — attempts to inject reStructuredText directives to read local files in NiceGUI applications.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect NiceGUI RCE via Raw Directive
    description: Detects CVE-2026-45553 exploitation - Detects attempts to use the raw directive with a file parameter to read local files.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A local file disclosure vulnerability exists in the NiceGUI library, specifically affecting applications that utilize the `ui.restructured_text()` function with untrusted input. When a NiceGUI application passes attacker-controlled reStructuredText content to the `ui.restructured_text()` function, it's possible for an attacker to inject malicious Docutils directives to read arbitrary local files accessible to the NiceGUI server process. The vulnerability lies in the server-side rendering of reStructuredText using Docutils without proper sanitization or disabling of file insertion directives. This issue affects NiceGUI versions 3.11.1 and earlier and is identified as CVE-2026-45553. Successful exploitation allows attackers to potentially access sensitive information such as application `.env` files, database URLs, API tokens, and source code.

## Attack Chain

1. The attacker identifies a NiceGUI application that uses the `ui.restructured_text()` function.
2. The attacker finds an input field (e.g., form field, query parameter) that passes data to `ui.restructured_text()`.
3. The attacker crafts malicious reStructuredText content containing a file inclusion directive, such as `.. include:: /etc/passwd`.
4. The attacker injects the malicious payload into the identified input field.
5. The NiceGUI server processes the reStructuredText content via Docutils, rendering the injected directive.
6. Docutils reads the specified local file (`/etc/passwd` in this example) from the server's filesystem.
7. The content of the file is embedded into the generated HTML output.
8. The attacker views the application, revealing the contents of the targeted local file in the HTML.

## Impact

Successful exploitation of this vulnerability (CVE-2026-45553) allows an attacker to read arbitrary files on the server's filesystem, provided the NiceGUI server process has the necessary permissions. This can lead to the disclosure of sensitive information, including application configuration files (`.env`), database credentials, API keys, session secrets, OAuth credentials, Docker/Kubernetes secrets, and application source code. The vulnerability can result in significant confidentiality loss and potentially compromise the entire application or infrastructure. Applications are only vulnerable when they pass untrusted or user-controlled reStructuredText input to the `ui.restructured_text()` function.

## Recommendation

- Upgrade to NiceGUI version 3.11.2 or later, which includes the recommended fix to disable unsafe Docutils features.
- Deploy the Sigma rule `Detect NiceGUI RCE Attempts via Restructured Text` to monitor for exploitation attempts by detecting the presence of file inclusion directives in HTTP requests to NiceGUI applications.
- Apply the remediation steps outlined in the advisory (https://github.com/advisories/GHSA-jfrm-rx66-g536) which disables file insertion and raw directives in the Docutils configuration.
- If upgrading is not immediately feasible, sanitize user-supplied input before passing it to `ui.restructured_text()` to remove or escape potentially malicious reStructuredText directives.
