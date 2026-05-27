---
title: Taipy 4.1.1 Path Traversal Vulnerability (CVE-2026-48544)
slug: 2026-05-taipy-path-traversal
description: Taipy 4.1.1 contains a path traversal vulnerability (CVE-2026-48544) in the ElementLibrary.get_resource() method that allows unauthenticated attackers to escape the intended module directory by exploiting an incomplete path containment check, enabling unauthorized file access outside the intended library directory.
date: "2026-05-27T15:17:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
vendors:
  - Taipy
products:
  - Taipy 4.1.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-48544
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48544
rules:
  - title: Detect CVE-2026-48544 Exploitation — Taipy Path Traversal
    description: Detects CVE-2026-48544 exploitation — attempts to access files outside the intended library directory in Taipy via path traversal.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-48544 Exploitation Attempt — Taipy Path Traversal with Trailing Separator Bypass
    description: Detects CVE-2026-48544 exploitation attempt — crafted GET requests exploiting the missing trailing path separator check in Taipy's ElementLibrary.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Taipy is vulnerable to a path traversal flaw, identified as CVE-2026-48544, affecting version 4.1.1. The vulnerability exists in the `ElementLibrary.get_resource()` method within the `taipy/gui/extension/library.py` file. This vulnerability enables unauthenticated attackers to bypass intended directory restrictions, potentially leading to the exposure of sensitive files. The root cause lies in an insufficient path containment check that utilizes `str.startswith()` without enforcing a trailing path separator, allowing attackers to craft malicious GET requests with path traversal sequences to access files outside the intended library directory. Successful exploitation could result in the unauthorized disclosure of application source code, configuration files, or other sensitive data.

## Attack Chain

1. The attacker identifies a Taipy 4.1.1 instance running a web application.
2. The attacker crafts a malicious GET request targeting the `ElementLibrary.get_resource()` endpoint.
3. The crafted GET request includes path traversal sequences (e.g., `../`) in the resource path.
4. The flawed `str.startswith()` check in `ElementLibrary.get_resource()` fails to properly sanitize the path due to the absence of a trailing path separator.
5. Flask's path converter and Werkzeug's WSGI layer preserve the traversal segments.
6. The server resolves the manipulated path, allowing access to files outside the intended library directory.
7. The attacker retrieves sensitive files, such as application source code or configuration files.

## Impact

Successful exploitation of this path traversal vulnerability (CVE-2026-48544) allows unauthenticated attackers to read arbitrary files on the server hosting the vulnerable Taipy application. This unauthorized file access can lead to the disclosure of sensitive information, including application source code, configuration files containing credentials, or internal documentation. The severity of the impact depends on the nature of the exposed files and the attacker's ability to leverage this information for further malicious activities.

## Recommendation

- Upgrade to a patched version of Taipy that includes commit `129fd40` which addresses CVE-2026-48544.
- Deploy the Sigma rule `Detect CVE-2026-48544 Exploitation — Taipy Path Traversal` to your SIEM to detect exploitation attempts based on suspicious URI patterns.
- Implement web application firewall (WAF) rules to filter out requests containing path traversal sequences targeting the `ElementLibrary.get_resource()` endpoint.
- Regularly review and update input validation and sanitization routines to prevent path traversal vulnerabilities in other parts of the application.
