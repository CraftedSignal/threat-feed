---
title: FacturaScripts Remote Code Execution via Zip Slip Vulnerability
slug: 2024-01-facturascripts-rce
description: FacturaScripts is vulnerable to remote code execution due to insufficient validation of file paths within uploaded ZIP archives, allowing a Zip Slip attack and arbitrary file write leading to RCE.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - zip-slip
  - rce
  - factura scripts
vendors:
  - FacturaScripts
products:
  - facturascripts (<= 2025.71)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: PHP'
references:
  - https://github.com/advisories/GHSA-3pgc-xqg9-cfr6
  - https://github.com/ZeroXJacks/CVEs/blob/main/2026/CVE-2026-27891.md
rules:
  - title: Detect FacturaScripts Plugin Upload with Path Traversal
    description: Detects FacturaScripts plugin uploads with filenames containing path traversal sequences (../) that could lead to Zip Slip vulnerability exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Web Shell via GET Parameter
    description: Detects HTTP requests accessing a PHP file with a 'cmd' GET parameter, indicating potential web shell activity.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FacturaScripts, a web application, is vulnerable to a critical remote code execution (RCE) vulnerability (CVE-2026-27891) due to a Zip Slip flaw in the plugin upload mechanism. Specifically, the `Plugins::add()` function fails to properly validate file paths within uploaded ZIP archives. This allows an attacker to inject malicious PHP code into arbitrary locations on the server by crafting a ZIP archive with path traversal sequences. The vulnerability affects FacturaScripts versions 2025.71 and earlier. Successful exploitation allows an attacker to gain complete control of the affected system, potentially leading to data theft, system compromise, or denial of service. This poses a significant threat to organizations using FacturaScripts for their business operations.

## Attack Chain

1.  Attacker crafts a malicious ZIP archive containing a PHP file with a web shell, such as `rce.php`. The malicious filename includes path traversal sequences like `MyPlugin/../../rce.php`.
2.  The attacker logs into the FacturaScripts web application with administrative privileges.
3.  The attacker navigates to the plugin management section.
4.  The attacker uploads the crafted malicious ZIP archive through the "Add Plugin" functionality.
5.  The `Plugins::add()` function processes the uploaded ZIP file, bypassing the single root folder check with the `ValidPluginName` prefix, but fails to properly sanitize the file paths.
6.  The ZIP archive is extracted, and the malicious PHP file `rce.php` is written to an arbitrary location outside the intended plugin directory due to the `../../` path traversal sequence.
7.  The attacker sends an HTTP request to the injected PHP web shell (e.g., `https://target.com/rce.php?cmd=whoami`) with commands to execute.
8.  The web server executes the attacker's command, granting the attacker arbitrary code execution on the server.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve Remote Code Execution (RCE) on the FacturaScripts server. The attacker can read all database configurations and files, modify any file on the server, and potentially delete the entire installation. This can lead to complete compromise of the system, data theft, and disruption of business operations. Given the sensitive nature of data often managed by FacturaScripts, such as financial records and customer information, the impact is considered high across confidentiality, integrity, and availability.

## Recommendation

*   Upgrade FacturaScripts to a patched version beyond 2025.71 to remediate CVE-2026-27891.
*   Implement server-side input validation to sanitize uploaded filenames and prevent path traversal during ZIP extraction.
*   Monitor web server logs for suspicious HTTP requests to potentially injected PHP shells such as `/rce.php` using a rule like "Detect Access to Web Shell via GET Parameter".
*   Deploy the Sigma rule "Detect FacturaScripts Plugin Upload with Path Traversal" to identify malicious ZIP uploads.
