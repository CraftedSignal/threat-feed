---
title: Authentication Bypass Vulnerability in Apache Answer
slug: 2026-10-apache-answer-auth-bypass
description: Apache Answer versions 2.0.2 and earlier contain an authentication bypass vulnerability in the reaction API that allows unauthorized users to access restricted metadata and manipulate content reactions.
date: "2026-10-19T20:12:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:apache:answer:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - apache
vendors:
  - Apache
products:
  - Answer (<= 2.0.2)
cves:
  - id: CVE-2026-90910
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90910
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache Answer to version 2.0.3
      owner: IT Operations
      addresses: CVE-2026-90910
      evidence: Users are recommended to upgrade to version 2.0.3, which fixes the issue.
---

Apache Answer versions 2.0.2 and earlier contain a critical authentication bypass vulnerability, identified as CVE-2026-90910. The vulnerability resides within the application's reaction API, which fails to properly enforce content visibility controls. This oversight allows unauthenticated or unauthorized users to interact with the API to read reaction metadata associated with restricted or private content, as well as add or remove reactions on content they should not have access to. The vulnerability carries a CVSS 3.1 base score of 9.8, indicating the potential for significant unauthorized data access within the platform. Organizations currently running affected versions of Apache Answer are strongly advised to upgrade to version 2.0.3 to mitigate this risk.

## Impact

Successful exploitation of this vulnerability allows unauthorized users to bypass existing access control mechanisms to read sensitive metadata and modify interactions on restricted content. This could result in information disclosure and the manipulation of user activity data, impacting the integrity and confidentiality of discussions within the Apache Answer instance.

## Recommendation

* Upgrade all Apache Answer installations to version 2.0.3 or later to patch CVE-2026-90910.
* Monitor web server logs for high volumes of unexpected or anomalous requests targeting the reaction API endpoints if patching cannot be performed immediately.
