---
title: Stored XSS in Sakai Conversations
slug: 2026-08-sakai-xss
description: The Sakai Conversations tool suffers from a stored cross-site scripting (XSS) vulnerability, CVE-2026-54049, allowing authenticated users to execute arbitrary JavaScript in the browsers of other site members.
date: "2026-08-24T21:58:07Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Sakai
products:
  - sakai-conversations-impl (23.0-23.3)
  - sakai-kernel-impl (23.0-23.3)
  - rubrics-impl (23.0-23.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker with any site membership (student role or higher) can... inject arbitrary HTML and JavaScript.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: The frontend renders them using LitElement's unsafeHTML() directive, resulting in stored cross-site scripting.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w2x5-gv52-9ccv
rules:
  - title: Detects CVE-2026-54049 Exploitation - Stored XSS in Sakai Conversations
    description: Detects potential stored XSS injection attempts via POST requests to the Sakai Conversations API containing common XSS vectors.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Review Sakai access logs for POST requests to /api/sites/*/topics for the specified pattern
      owner: Security Operations
      due: 24h
      evidence: Source provides specific vulnerable endpoints.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the patched version once released
      owner: IT Operations
      addresses: CVE-2026-54049
      evidence: Fix committed in 2696b4b48cbef2e81512f52f84f7477adff78b27
---

The Sakai Conversations tool, part of the Sakai LMS framework, contains a stored XSS vulnerability (CVE-2026-54049) affecting versions 23.0 through 23.3. The vulnerability stems from the Conversations REST API failing to sanitize user-provided message input before persisting it to the database, combined with the frontend's use of LitElement's `unsafeHTML()` directive to render these messages. 

An attacker with any authenticated site role can inject malicious payloads via the `message` field in the `/api/sites/{siteId}/topics` or `/api/sites/{siteId}/topics/{topicId}/posts` endpoints. When other users navigate to the affected conversation thread, the frontend renders the unsanitized HTML, resulting in arbitrary JavaScript execution within the victim's session. This vulnerability poses a significant risk to university environments, as it facilitates account takeover, unauthorized access to sensitive course data, and large-scale compromise of student accounts. A fix has been committed in commit `2696b4b48cbef2e81512f52f84f7477adff78b27`.

## Attack Chain

1. Attacker authenticates to a Sakai instance with at least student-level permissions.
2. Attacker selects a site where the Conversations tool is enabled.
3. Attacker crafts a malicious payload containing JavaScript, such as `<img src=x onerror=alert(1)>`.
4. Attacker sends an HTTP POST request to `/api/sites/{siteId}/topics` or `/api/sites/{siteId}/topics/{topicId}/posts` with the malicious payload in the `message` JSON field.
5. The Conversations service layer accepts the input without sanitization and commits the raw payload to the database.
6. A victim user navigates to the affected topic or post in the Sakai frontend.
7. The LitElement web component fetches the data and renders the payload via `unsafeHTML()`.
8. The browser executes the malicious script in the context of the victim's session, leading to potential data exfiltration or session hijacking.

## Impact

Successful exploitation allows an attacker to execute arbitrary code within the browsers of all users viewing the compromised thread. In a university setting, this can lead to the mass exfiltration of gradebook data, course content, and unauthorized administrative actions if a privileged user views the content. The scope includes any deployment of Sakai 23.0 through 23.3.

## Recommendation

1. Upgrade Sakai installations to a version containing the fix for CVE-2026-54049 once released.
2. Implement strict Content Security Policy (CSP) headers to prevent the execution of unauthorized inline scripts.
3. Deploy web application firewall (WAF) rules to detect and block common XSS payloads in JSON bodies directed at `/api/sites/*/topics` and `/api/sites/*/topics/*/posts` endpoints.
4. Review access control lists for the Conversations tool to ensure only trusted users have the ability to contribute to threads.
