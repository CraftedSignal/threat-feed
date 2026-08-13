---
title: Cross-Site Request Forgery in phpList Administrator Deletion
slug: 2026-08-phplist-csrf
description: A CSRF vulnerability in phpList versions prior to 3.7.0-RC5 allows authenticated administrators to be tricked into deleting other administrator accounts via a crafted GET request.
date: "2026-08-13T19:44:01Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - web-vulnerability
  - csrf
  - php
vendors:
  - phpList
products:
  - phpList (< 3.7.0-RC5)
cves:
  - id: CVE-2026-73482
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73482
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch phpList instances to 3.7.0-RC5 or later.
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommends upgrading to 3.7.0-RC5.
  mitigation_plan:
    - priority: immediate
      action: Review administrative logs for GET-based admin deletion requests.
      owner: Security Operations
      addresses: CVE-2026-73482
      evidence: Vulnerability triggers via ?page=admins&delete=N GET request.
---

phpList versions prior to 3.7.0-RC5 contain a cross-site request forgery (CSRF) vulnerability located in the administrative management module, specifically within 'lists/admin/admins.php'. The vulnerability stems from an insecure implementation of the administrator deletion action, which is triggered via a GET request using the parameter '?page=admins&delete=N'. While phpList includes a central 'verifyCsrfGetToken' check, this implementation sets 'enforce=false', effectively bypassing protection if the token parameter is omitted from the request. A remote attacker can exploit this by deceiving a logged-in super-administrator into accessing a crafted URL - such as one embedded as an image source or hidden iframe within a phishing email - to silently remove existing administrator accounts from the system. This threat is particularly critical for self-hosted instances where administrative control is concentrated in a single super-administrator account.

## Impact

Successful exploitation results in the unauthorized deletion of administrative accounts within the phpList instance. This can lead to administrative lockout, service disruption, and the potential for an attacker to gain further unauthorized access if accounts are recreated with compromised credentials or if administrative roles are altered during the incident. There is no evidence of widespread exploitation in the wild, but the impact is significant for organizations relying on phpList for email campaign management.

## Recommendation

* Upgrade phpList installations to version 3.7.0-RC5 or later to resolve the underlying CSRF vulnerability.
* Audit administrative access logs in phpList for anomalous deletion activities initiated via GET requests.
* Implement additional authentication controls for administrative actions that modify user roles or delete accounts.
