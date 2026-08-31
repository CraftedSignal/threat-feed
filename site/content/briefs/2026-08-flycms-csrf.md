---
title: Cross-Site Request Forgery in Sunkaifei Flycms
slug: 2026-08-flycms-csrf
description: CVE-2024-22939 is a Cross-Site Request Forgery (CSRF) vulnerability in Sunkaifei Flycms version 1.0 allowing unauthorized modification of article categories via the category_edit endpoint.
date: "2026-08-31T09:23:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sunkaifei:flycms:1.0:*:*:*:*:*:*:*
tags:
  - web-application
  - csrf
  - cve-2024-22939
vendors:
  - Sunkaifei
products:
  - Flycms (1.0)
cves:
  - id: CVE-2024-22939
    cvss: 8.8
    epss: 0.0069
rules:
  - title: Detect Potential CSRF Exploitation Attempts Against Flycms
    description: Detects unauthorized POST requests to the article category edit endpoint of Flycms, which may indicate a CSRF attempt.
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review web access logs for activity related to /system/article/category_edit
      owner: SOC
      due: 24h
      evidence: Source document identifies the endpoint as vulnerable to CSRF
  mitigation_plan:
    - priority: immediate
      action: Isolate vulnerable Flycms instances until secure configuration or update is implemented
      owner: IT Operations
      addresses: CVE-2024-22939
      evidence: Exploit availability increases risk
---

CVE-2024-22939 describes a Cross-Site Request Forgery (CSRF) vulnerability discovered in Sunkaifei Flycms version 1.0. The vulnerability resides in the '/system/article/category_edit' component of the application. An unauthenticated attacker can exploit this flaw by tricking an authenticated administrator into executing a malicious request, which leads to the unauthorized modification of article categories. The CVSS score for this vulnerability is 8.8, reflecting its potential for significant impact on data integrity and application management. A functional proof-of-concept (PoC) exploit has been published, increasing the risk of exploitation for organizations currently running this version.

## Attack Chain

1. Attacker identifies a target instance of Sunkaifei Flycms 1.0.
2. Attacker crafts a malicious HTML/JavaScript payload containing a hidden form targeting the '/system/article/category_edit' endpoint.
3. Attacker identifies a target user with administrative privileges who is currently authenticated to the Flycms instance.
4. Attacker uses social engineering to trick the authenticated administrator into visiting a malicious webpage or clicking a link containing the CSRF payload.
5. The victim's browser automatically includes their active session cookies when it sends the POST request to the application.
6. The server validates the session cookies and processes the unauthorized request to modify article categories.
7. The target application state is updated based on the attacker's parameters, resulting in unauthorized data modification.

## Impact

Successful exploitation allows an unauthenticated attacker to manipulate content management structures, potentially leading to unauthorized data alteration, disruption of article management, or further site defacement. If used in conjunction with other vulnerabilities, this could impact the overall confidentiality, integrity, and availability of the affected Flycms deployment.

## Recommendation

Detection engineering teams should prioritize identifying potential CSRF attempts directed at administrative endpoints.

- Monitor webserver logs for unauthorized POST requests to the '/system/article/category_edit' endpoint.
- Implement and enforce standard CSRF protection mechanisms (e.g., anti-CSRF tokens) within the application code to validate the origin of requests.
- Audit and restrict access to administrative interfaces and ensure that administrative sessions are protected by appropriate timeouts and secure cookie configurations.
- Given the lack of a vendor patch for version 1.0, consider moving to an alternative CMS or isolating the application environment until a secure update is provided.
