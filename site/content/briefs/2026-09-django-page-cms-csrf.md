---
title: CSRF and Stored XSS Vulnerability in django-page-cms
slug: 2026-09-django-page-cms-csrf
description: An improper CSRF protection flaw in django-page-cms versions up to 2.0.13 enables attackers to force authenticated editors to inject stored XSS payloads.
date: "2026-09-18T04:02:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:django:django_page_cms:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - csrf
  - xss
vendors:
  - Django
products:
  - django-page-cms (<= 2.0.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Signed-in editors visiting a malicious page can be tricked into storing unescaped content.
    confidence_band: high
cves:
  - id: CVE-2026-93456
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93456
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade django-page-cms to version > 2.0.13.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-93456 vulnerability advisory.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to latest patched version.
      owner: IT Operations
      addresses: CVE-2026-93456
      evidence: Source advisory
---

CVE-2026-93456 affects the django-page-cms package in all versions up to and including 2.0.13. The vulnerability arises because five administrative mutation views located in pages/admin/views.py lack adequate Cross-Site Request Forgery (CSRF) protection. By failing to validate the authenticity of requests to these endpoints, the application allows unauthorized state-changing operations if an authenticated user is coerced into interacting with attacker-controlled content. This flaw is primarily critical because it facilitates Cross-Site Request Forgery that can be leveraged to inject stored Cross-Site Scripting (XSS) payloads into the CMS. Once injected, these payloads are stored on the server and executed in the browsers of other users, including site visitors and administrators, potentially leading to session hijacking, defacement, or further unauthorized actions within the administrative dashboard.

## Impact

Successful exploitation allows remote attackers to perform unauthorized administrative actions on behalf of a logged-in user. By injecting malicious scripts into page content, an attacker can impact all site visitors, compromising the integrity of the web application and the confidentiality of administrative sessions. This vulnerability is significant for organizations using django-page-cms to manage content-heavy web portals.

## Recommendation

1. Upgrade django-page-cms to a version beyond 2.0.13 immediately.
2. Audit web server logs for suspicious POST requests originating from external referrers targeting the /admin/pages/ paths.
3. Review stored page content for injected script tags, specifically looking for unescaped JavaScript in fields managed by the admin panel.
