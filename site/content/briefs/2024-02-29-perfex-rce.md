---
title: Perfex CRM Unauthenticated Remote Code Execution via Insecure Deserialization
slug: 2024-02-29-perfex-rce
description: Perfex CRM is vulnerable to unauthenticated remote code execution (RCE) due to an autologin cookie being fed into unserialize().
date: "2024-02-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - perfex-crm
  - rce
  - insecure-deserialization
  - php
vendors:
  - Perfex
products:
  - Perfex CRM
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.reddit.com/r/netsec/comments/1rv6dqd/perfex_crm_autologin_cookie_fed_into_unserialize/
  - https://nullcathedral.com/posts/2026-03-16-perfex-crm-unauthenticated-rce-insecure-deserialization/
iocs:
  - type: url
    value: https://nullcathedral.com/posts/2026-03-16-perfex-crm-unauthenticated-rce-insecure-deserialization/
  - type: url
    value: https://www.reddit.com/r/netsec/comments/1rv6dqd/perfex_crm_autologin_cookie_fed_into_unserialize/
ioc_counts:
  url: 2
rules:
  - title: Detect Suspiciously Long autologin Cookie
    description: Detects autologin cookies with excessive length, potentially indicating serialized payloads.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - apache
  - title: Detect autologin cookie in URI
    description: Detects autologin cookie passed via GET instead of POST
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - apache
rules_count: 2
---

Perfex CRM, a customer relationship management software, is susceptible to an unauthenticated remote code execution vulnerability. This vulnerability stems from the application's handling of autologin cookies. The autologin cookie is directly passed into PHP's `unserialize()` function without proper sanitization. This allows an attacker to inject arbitrary PHP objects into the application's context, leading to remote code execution. This vulnerability allows unauthenticated attackers to execute arbitrary code on the server. Given the widespread use of CRM software and the ease of exploitation, this vulnerability poses a significant risk to organizations using Perfex CRM.

## Attack Chain

1. An attacker identifies a Perfex CRM instance exposed to the internet.
2. The attacker crafts a malicious PHP object designed to execute arbitrary code. This object could leverage existing classes within the Perfex CRM codebase, or potentially utilize PHP's built-in functions for code execution.
3. The malicious PHP object is serialized using PHP's `serialize()` function.
4. The serialized object is base64 encoded.
5. The base64 encoded string is set as the value of the `autologin` cookie in an HTTP request.
6. The attacker sends the crafted HTTP request to the Perfex CRM instance, targeting a page that processes the `autologin` cookie.
7. The Perfex CRM application receives the request and passes the value of the `autologin` cookie directly to the `unserialize()` function.
8. The `unserialize()` function reconstructs the malicious PHP object, triggering the execution of the attacker's arbitrary code. This can lead to complete system compromise, including data exfiltration, installation of malware, or defacement of the CRM system.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to execute arbitrary code on the server hosting Perfex CRM. This could lead to complete system compromise, including sensitive customer data exfiltration, installation of ransomware, or defacement of the CRM system. Organizations using vulnerable Perfex CRM instances are at high risk of data breaches, financial loss, and reputational damage.

## Recommendation

*   Inspect web server logs for requests with unusually long `autologin` cookie values to identify potential exploitation attempts (reference: web server logs).
*   Deploy the provided Sigma rule to detect exploitation attempts based on the structure of the `autologin` cookie (reference: Sigma rule).
*   Implement input validation on the `autologin` cookie to prevent the injection of serialized PHP objects (reference: vulnerability details).
