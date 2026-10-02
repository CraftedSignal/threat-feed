---
title: CVE-2026-103426 Stored Cross-Site Scripting in Relevanssi Premium
slug: 2026-10-relevanssi-xss
description: Relevanssi Premium for WordPress versions 2.31.4 and earlier contain a stored cross-site scripting vulnerability in the click-tracking feature that allows unauthenticated attackers to execute arbitrary web scripts.
date: "2026-10-02T08:23:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:relevanssi:premium:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
vendors:
  - Relevanssi
products:
  - Relevanssi Premium (<= 2.31.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages
    confidence_band: high
cves:
  - id: CVE-2026-103426
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103426
rules:
  - title: Detect CVE-2026-103426 Exploitation - XSS via Relevanssi _rt Parameter
    description: Detects exploitation of CVE-2026-103426 where an attacker submits a JavaScript payload in the _rt parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.007
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Relevanssi Premium to a patched version beyond 2.31.4
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable up to 2.31.4
    - action: Disable click-tracking feature in Relevanssi settings
      owner: IT Operations
      due: 4h
      evidence: Exploitation requires feature to be activated
  hunt_leads:
    - lead: Search logs for _rt parameter usage
      technique_id: T1059.007
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation target is the _rt parameter
  mitigation_plan:
    - priority: immediate
      action: Upgrade or disable vulnerable plugin feature
      owner: IT Operations
      addresses: CVE-2026-103426
      evidence: Source confirmed vulnerability existence
---

The Relevanssi Premium plugin for WordPress is susceptible to a stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-103426. This flaw affects all plugin versions up to and including 2.31.4. The vulnerability arises from inadequate input sanitization and output escaping within the plugin's click-tracking and logging functionality. When this specific feature is enabled, an attacker can supply malicious payloads via the '_rt' parameter. Because the plugin publicly exposes a valid '_rt_nonce' on search-result pages, unauthenticated attackers can obtain the necessary token to submit these payloads successfully. If executed, the injected scripts run within the context of a victim's session, potentially leading to unauthorized actions or data theft. This vulnerability highlights the risks associated with improper handling of user-supplied data in WordPress plugins that maintain server-side logs of client activity.

## Attack Chain

1. An attacker navigates to any search-results page on a WordPress site utilizing the vulnerable Relevanssi Premium plugin.
2. The attacker extracts the '_rt_nonce' value publicly visible in the page source or network request headers.
3. The attacker crafts an HTTP request containing a malicious JavaScript payload in the '_rt' parameter.
4. The attacker sends the crafted request to the plugin's click-tracking endpoint, incorporating the previously gathered '_rt_nonce'.
5. The server-side code processes the request, failing to sanitize the input before storing it in the plugin's logs or click-tracking database.
6. A target user (typically an administrator or authorized user) views a page or report where the plugin renders the stored, malicious payload.
7. The victim's browser executes the injected script in the context of the WordPress site.
8. The attacker achieves their objective, such as session hijacking, unauthorized configuration changes, or exfiltration of sensitive information.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the browser of users viewing the affected content. This could result in account takeover, unauthorized modification of site settings, or the exfiltration of sensitive session data. The scope of impact is contingent upon the privilege level of the users who view the injected scripts, with the highest impact occurring if administrators are targeted.

## Recommendation

Prioritize immediate remediation to neutralize the vulnerability.

* Patch CVE-2026-103426 by updating the Relevanssi Premium plugin to the version released after 2.31.4 as identified by the vendor.
* Disable the click-tracking and logging feature in the Relevanssi Premium plugin settings as a temporary mitigation until the update can be applied.
* Audit existing web server access logs for requests containing suspicious script content in the '_rt' parameter to identify potential past exploitation attempts.
* Deploy the Sigma rules below to monitor for exploitation attempts targeting the identified endpoint.
