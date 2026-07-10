---
title: AVideo CSRF Vulnerability Allows Admin Impersonation
slug: 2024-01-avideo-csrf
description: AVideo versions 29.0 and prior contain a CSRF vulnerability in admin-only JSON endpoints, allowing attackers to perform unauthorized actions if they can lure a logged-in administrator to visit a malicious page.
date: "2024-01-21T23:59:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - avideo
  - csrf
  - web-application
  - vulnerability
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-40926
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40926
rules:
  - title: AVideo CSRF - Category Modification Attempt
    description: Detects potential CSRF attacks targeting AVideo category modification endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: AVideo CSRF - Plugin Update Script Execution Attempt
    description: Detects potential CSRF attacks attempting to trigger plugin update scripts in AVideo.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is vulnerable to a Cross-Site Request Forgery (CSRF) attack. Specifically, versions 29.0 and earlier fail to properly validate CSRF tokens in three admin-only JSON endpoints: `objects/categoryAddNew.json.php`, `objects/categoryDelete.json.php`, and `objects/pluginRunUpdateScript.json.php`.  These endpoints only perform a role check (`Category::canCreateCategory()` / `User::isAdmin()`) but lack `isGlobalTokenValid()` or `forbidIfIsUntrustedRequest()` validation before performing state-changing actions against the database.  This omission allows an attacker to potentially create, update, or delete categories and force the execution of an installed plugin's `updateScript()` method.  The vulnerability was addressed in commit ee5615153c40628ab3ec6fe04962d1f92e67d3e2.

## Attack Chain

1. An attacker crafts a malicious HTML page containing a CSRF exploit targeting one of the vulnerable AVideo endpoints (`objects/categoryAddNew.json.php`, `objects/categoryDelete.json.php`, `objects/pluginRunUpdateScript.json.php`).
2. The attacker distributes the malicious page via email, social media, or other means, attempting to lure a logged-in AVideo administrator to visit it.
3. If the administrator visits the page while logged into AVideo, the malicious page silently sends a request to the vulnerable AVideo endpoint in the background.
4. Due to the lack of CSRF token validation on the targeted endpoints, the request is processed as if it originated from the administrator.
5. Depending on the targeted endpoint, the attacker can create a new category, delete an existing category, or trigger the execution of an `updateScript()` method of an installed plugin.
6. If the attacker triggers the execution of a plugin's `updateScript()` method, they gain arbitrary code execution within the context of the AVideo server.
7.  The attacker uses this code execution to establish persistence or further compromise the AVideo server.
8. The attacker can then exfiltrate sensitive video content or pivot to other systems within the network.

## Impact

Successful exploitation of this CSRF vulnerability allows an attacker to impersonate a logged-in AVideo administrator.  This can lead to unauthorized modification or deletion of video categories, potentially disrupting the platform's content organization.  More critically, triggering the `updateScript()` method of an installed plugin can lead to arbitrary code execution on the AVideo server, potentially resulting in complete system compromise and sensitive data theft. This vulnerability affects any AVideo instance running version 29.0 or prior.

## Recommendation

*   Upgrade AVideo installations to a version containing the fix from commit ee5615153c40628ab3ec6fe04962d1f92e67d3e2.
*   Deploy the Sigma rule provided below to detect attempts to access the vulnerable endpoints without a valid CSRF token based on `category: webserver` and `product: linux`.
*   Monitor web server logs for POST requests to the vulnerable endpoints (`objects/categoryAddNew.json.php`, `objects/categoryDelete.json.php`, `objects/pluginRunUpdateScript.json.php`) as documented in the Attack Chain.
