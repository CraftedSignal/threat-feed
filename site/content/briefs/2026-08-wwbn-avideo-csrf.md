---
title: 'CVE-2026-58003: Cross-Site Request Forgery in WWBN AVideo'
slug: 2026-08-wwbn-avideo-csrf
description: WWBN AVideo versions through commit 9c39d8c8 contain a CSRF vulnerability in the releaseVideoNow.json.php endpoint that allows unauthenticated attackers to force administrative users to publish embargoed videos.
date: "2026-08-22T13:30:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - web-application
  - csrf
  - cve-2026-58003
vendors:
  - WWBN
products:
  - AVideo (<= commit 9c39d8c8)
cves:
  - id: CVE-2026-58003
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58003
  - https://github.com/WWBN/AVideo/security/advisories/GHSA-q8cg-7x7q-c4g2
  - https://www.vulncheck.com/advisories/wwbn-avideo-cross-site-request-forgery-via-releasevideonow-json-php
rules:
  - title: Detect CVE-2026-58003 Exploitation Attempt - Suspicious GET request to releaseVideoNow.json.php
    description: Detects potential CSRF exploitation attempts targeting the releaseVideoNow.json.php endpoint via GET requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch WWBN AVideo to the latest version to remediate CVE-2026-58003.
      owner: IT Operations
      due: 48h
      evidence: Official CVE vulnerability report
  hunt_leads:
    - lead: Search logs for GET requests to releaseVideoNow.json.php with external referers.
      technique_id: T1521
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Vulnerability allows state-changing GET requests without CSRF protection.
  mitigation_plan:
    - priority: immediate
      action: Configure WAF to block GET requests to the vulnerable endpoint from unauthorized referers.
      owner: IT Operations
      addresses: CVE-2026-58003
      evidence: Vulnerability allows exploitation via GET request.
---

WWBN AVideo, an open-source video platform, contains a cross-site request forgery (CSRF) vulnerability tracked as CVE-2026-58003, affecting all versions through commit 9c39d8c8. The vulnerability resides in the 'releaseVideoNow.json.php' endpoint, which fails to implement necessary authenticity checks and erroneously accepts GET requests for state-changing operations. 

An attacker can exploit this by enticing an authenticated administrator to visit a malicious webpage containing a crafted GET request. The request, when executed within the administrator's browser, uses the active session cookie to invoke the 'releaseVideoNow.json.php' endpoint. By manipulating the 'videos_id' parameter in this request, the attacker can force the permanent publication of videos that were intended to remain in an embargoed or private state. This vulnerability poses a significant risk to the integrity of sensitive video content managed on the platform.

## Attack Chain

1. The attacker identifies a target administrative user who is likely to have an active session in the AVideo application.
2. The attacker crafts a malicious URL pointing to the vulnerable 'releaseVideoNow.json.php' endpoint on the target AVideo server.
3. The crafted URL includes the 'videos_id' parameter corresponding to an embargoed video the attacker intends to publish.
4. The attacker delivers the malicious URL to the administrator via a phishing email, a compromised website, or an embedded iframe in a site visited by the administrator.
5. The administrator, while logged into the AVideo application, clicks the link or visits the page containing the malicious request.
6. The victim's browser automatically includes the legitimate AVideo session cookies with the GET request to the AVideo server.
7. The AVideo server processes the request as a legitimate administrative action due to the presence of the session cookie.
8. The embargoed video is permanently published on the platform without the administrator's knowledge or consent.

## Impact

Successful exploitation results in the unauthorized publication of embargoed or private video content. This can lead to the premature release of sensitive organizational, media, or proprietary information, potentially damaging the victim organization's reputation or violating distribution agreements. The scope includes any WWBN AVideo installation running the affected commit or earlier.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:

* Apply the security patch provided by WWBN in the official GitHub repository for CVE-2026-58003 to mitigate the underlying endpoint vulnerability.
* Monitor web server access logs for anomalous GET requests directed to 'releaseVideoNow.json.php' that originate from referrers outside the expected application domain.
* Deploy web application firewall (WAF) rules to inspect and challenge or block external requests to 'releaseVideoNow.json.php' that do not originate from authenticated application workflows.
* Enable strict SameSite cookie attributes on application session cookies to mitigate the risk of cross-site request forgery.
