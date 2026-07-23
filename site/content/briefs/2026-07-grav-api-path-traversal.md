---
title: Grav API Plugin Path Traversal Vulnerability (CVE-2026-65896)
slug: 2026-07-grav-api-path-traversal
description: An authenticated API caller with 'api.pages.write' permission in Grav API Plugin (Composer package getgrav/grav-plugin-api) before version 1.0.10 can exploit a path traversal vulnerability (CVE-2026-65896). The 'POST /pages/{route}/move' endpoint's 'slug' field is not properly sanitized, allowing attackers to use path traversal sequences (e.g., '01.home/../../../pwned'). This enables them to move an entire page directory, including content and media, to an arbitrary writable location outside the intended 'user/pages/' directory, potentially leading to unauthorized file manipulation or system compromise.
date: "2026-07-23T12:23:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - vulnerability
vendors:
  - Grav
products:
  - Grav API Plugin (before 1.0.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated API caller with the api.pages.write permission can supply path traversal sequences (e.g., 01.home/../../../pwned) to move an entire page directory (content and media) to an arbitrary writable location outside user/pages/, including outside the Grav installation.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An authenticated API caller with the api.pages.write permission
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: move an entire page directory (content and media) to an arbitrary writable location outside user/pages/, including outside the Grav installation.
    confidence_band: med
cves:
  - id: CVE-2026-65896
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65896
---

CVE-2026-65896 describes a path traversal vulnerability in the Grav API Plugin (Composer package getgrav/grav-plugin-api) versions prior to 1.0.10. This flaw affects the `POST /pages/{route}/move` endpoint, specifically within the `PagesController::move()` function, where the `slug` field from the request body is not adequately validated. The sanitization process only strips leading periods, failing to neutralize path traversal sequences like '/' or '..'. An authenticated API caller possessing the `api.pages.write` permission can leverage this vulnerability to move entire page directories, including their content and media files, to arbitrary writable locations outside the intended `user/pages/` directory, and potentially outside the Grav installation entirely. This could lead to unauthorized modification, disruption of services, or data exposure by relocating critical application components.

## Attack Chain

1. An attacker obtains valid API credentials for a Grav instance, ensuring they have the `api.pages.write` permission.
2. The attacker crafts a malicious HTTP POST request targeting the `/pages/{route}/move` endpoint of the Grav API.
3. Within the POST request body, the attacker includes a `slug` parameter containing path traversal sequences, such as `01.home/../../../pwned`.
4. The Grav API Plugin, specifically `PagesController::move()`, receives this request.
5. The vulnerability in the plugin causes inadequate sanitization of the `slug` parameter, allowing the path traversal sequences to be processed.
6. The Grav application interprets these sequences as legitimate directory navigation instructions.
7. The application then moves the specified Grav page directory (including its content and media) to the arbitrary, attacker-controlled writable location specified by the traversal sequences.
8. This results in unauthorized file system modifications, potentially leading to data manipulation, application disruption, or a stepping stone for further compromise of the Grav installation or underlying server.

## Impact

A successful exploitation of CVE-2026-65896 can result in significant unauthorized file system manipulation. Attackers can move entire Grav page directories to arbitrary locations, including outside the Grav installation path. This can lead to disruption of the web application, data exposure if sensitive files are moved to publicly accessible locations, or even system compromise if critical configuration or system files are overwritten or moved to facilitate further attacks. The CVSS v3.1 Base Score of 7.1 indicates a high severity risk, emphasizing the potential for major damage to confidentiality, integrity, and availability of the Grav installation.

## Recommendation

* Upgrade Grav API Plugin (Composer package getgrav/grav-plugin-api) to version 1.0.10 or newer immediately to patch CVE-2026-65896.
* Implement a Web Application Firewall (WAF) or API Gateway capable of inspecting HTTP POST body parameters for path traversal sequences like `../`, `/./`, and absolute paths in requests to API endpoints, particularly `/pages/*/move`.
* Monitor API authentication logs for unusual access patterns or the creation/modification of highly privileged API keys that could be used to exploit vulnerabilities requiring authenticated access.
