---
title: Missing Authorization Vulnerability in Dolusoft Sonlogger
slug: 2026-08-sonlogger-auth-bypass
description: An unauthenticated access control vulnerability (CVE-2026-16471) in Dolusoft Sonlogger allows remote attackers to bypass ACLs and access restricted functionality.
date: "2026-08-17T14:47:08Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Dolusoft Software Technologies
products:
  - Sonlogger
cves:
  - id: CVE-2026-16471
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16471
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0849
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Sonlogger to version 6.7.4.8 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-16471 advisory recommendation
---

Dolusoft Software Technologies Sonlogger versions 6.6.6 through 6.7.4.7 contain a missing authorization vulnerability, tracked as CVE-2026-16471. This security flaw stems from insufficient enforcement of access control lists (ACLs) within the application's functionality. Because the vulnerability is exploitable without authentication, remote, unauthenticated attackers can leverage this defect to interact with sensitive features or internal endpoints of the Sonlogger platform that should otherwise be restricted. This exposure poses a significant risk to data confidentiality, as attackers may gain unauthorized access to logs, configurations, or administrative functions. The vulnerability was reported by the Computer Emergency Response Team of the Republic of Turkey. Organizations utilizing Sonlogger within the affected version range are urged to upgrade to version 6.7.4.8 or later to mitigate the risk of unauthorized access.

## Attack Chain

1. Attacker performs network reconnaissance to identify internet-facing instances of Sonlogger.
2. Attacker probes the application to determine the version number and target reachable endpoints.
3. Attacker identifies an endpoint or function that is not properly constrained by server-side authorization checks.
4. Attacker crafts a specific HTTP request targeting the exposed functionality.
5. The application fails to validate the user session or authorization token for the requested operation.
6. The application processes the request and executes the privileged function.
7. Attacker extracts sensitive data, modifies configurations, or performs other unauthorized actions permitted by the vulnerable endpoint.

## Impact

Successful exploitation of CVE-2026-16471 enables unauthenticated remote attackers to bypass authorization controls, potentially leading to unauthorized data exfiltration or administrative manipulation of the Sonlogger platform. This vulnerability is rated with a CVSS v3.1 base score of 7.5, indicating a high impact on confidentiality.

## Recommendation

* Immediately upgrade all instances of Sonlogger to version 6.7.4.8 or newer to resolve the missing authorization flaw identified in CVE-2026-16471.
* Audit access logs for abnormal requests to administrative or management endpoints originating from unauthorized source IP addresses.
* Restrict network access to Sonlogger management interfaces, ensuring they are not exposed to the public internet unless required.
