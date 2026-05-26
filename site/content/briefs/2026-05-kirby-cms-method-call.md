---
title: Kirby CMS Arbitrary Method Call Vulnerability via REST API
slug: 2026-05-kirby-cms-method-call
description: Kirby CMS is vulnerable to arbitrary method call via REST API search and collection query endpoints, allowing attackers to execute sensitive methods like password disclosure or privilege escalation, patched in versions 4.9.1 and 5.4.1.
date: "2026-05-26T23:52:40Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - arbitrary-code-execution
  - privilege-escalation
  - web-application
vendors:
  - getkirby
products:
  - cms (<= 4.9.0)
  - cms (>= 5.0.0, <= 5.4.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1212
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-86rh-h242-j8xp
  - https://github.com/getkirby/kirby/releases/tag/4.9.1
  - https://github.com/getkirby/kirby/releases/tag/5.4.1
  - CVE-2026-44174
rules:
  - title: Detect CVE-2026-44174 Exploitation Attempt — Kirby CMS Arbitrary Method Call in REST API
    description: Detects CVE-2026-44174 exploitation attempt — Suspicious HTTP request to Kirby CMS REST API endpoints with potentially malicious method calls in query parameters.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1212
    data_sources:
      - webserver
  - title: Detect CVE-2026-44174 Exploitation – Kirby CMS loginPasswordless() API Call
    description: Detects CVE-2026-44174 exploitation — An API call to loginPasswordless() could indicate an attempt to elevate privileges.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1212
    data_sources:
      - webserver
rules_count: 2
---

Kirby CMS versions before 4.9.1 and versions 5.0.0 through 5.4.0 are susceptible to an arbitrary method call vulnerability via its REST API. The vulnerability stems from insufficient validation of model attributes used in collection queries. An authenticated attacker with access to the Panel can exploit this to invoke arbitrary model methods, potentially leading to sensitive data disclosure (e.g., password hashes, filesystem paths) or unauthorized actions like privilege escalation or data deletion. This issue affects all Kirby sites where potential attackers are authenticated Panel users. The vulnerability was reported responsibly and has been addressed in Kirby versions 4.9.1 and 5.4.1.

## Attack Chain

1. An attacker authenticates to the Kirby Panel.
2. The attacker crafts a malicious REST API request targeting a collection endpoint such as `/site/children` or `/users`.
3. The attacker includes a collection query parameter (e.g., `filter`, `sort`) with an arbitrary model method as the attribute.
4. The vulnerable Kirby CMS endpoint processes the request without proper validation of the model attribute.
5. The specified model method is executed, potentially disclosing sensitive information like password hashes via `password()` or filesystem paths via `root()`.
6. Alternatively, the attacker could trigger impactful actions like privilege escalation by calling `loginPasswordless()` or data deletion by calling `delete()`.
7. The attacker gains unauthorized access or causes data loss, depending on the method called and the attacker's permissions.

## Impact

Successful exploitation of this vulnerability allows attackers to disclose sensitive information or perform unauthorized actions. This can lead to complete compromise of the Kirby CMS instance, including unauthorized access to content, modification of data, or denial of service.  The impact is high, affecting all Kirby sites with authenticated Panel users, leading to privilege escalation or data loss, depending on the permissions of the authenticated user.

## Recommendation

*   Upgrade to Kirby CMS version 4.9.1, 5.4.1, or later to patch CVE-2026-44174.
*   Implement input validation on REST API endpoints to prevent arbitrary method calls.
*   Monitor web server logs for suspicious API requests containing potentially malicious method calls in query parameters.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
