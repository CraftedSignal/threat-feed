---
title: Unauthenticated Remote Code Execution in goodoneuz/pay-uz Laravel Package
slug: 2024-01-laravel-rce
description: A critical unauthenticated remote code execution vulnerability exists in the goodoneuz/pay-uz Laravel package (<= 2.2.24) due to direct user-controlled input being written to executable PHP files via the /payment/api/editable/update endpoint.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - CVE-2026-31843
  - RCE
  - Laravel
  - webserver
vendors:
  - goodoneuz
products:
  - pay-uz
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-31843
    cvss: 9.8
    epss: 0.01135
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31843
rules:
  - title: Detect Pay-UZ Laravel RCE Attempt
    description: Detects attempts to exploit the RCE vulnerability (CVE-2026-31843) in the goodoneuz/pay-uz Laravel package by monitoring HTTP POST requests to the /payment/api/editable/update endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - rce
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Modification in Laravel Payment Directory
    description: Detects suspicious file modifications within the Laravel payment directory, which could indicate exploitation of the RCE vulnerability.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The goodoneuz/pay-uz Laravel package, specifically versions 2.2.24 and earlier, is vulnerable to unauthenticated remote code execution (RCE). The vulnerability, identified as CVE-2026-31843, resides in the `/payment/api/editable/update` endpoint. This endpoint is insecurely exposed via `Route::any()` without requiring any form of authentication. This allows any remote attacker to directly write arbitrary, user-supplied input into existing PHP files. Because these files are payment hooks executed via `require()` during standard payment processing, attackers can inject and execute arbitrary code on the server. This RCE vulnerability poses a severe risk to applications utilizing the vulnerable package, potentially leading to full system compromise.

## Attack Chain

1.  The attacker sends a crafted HTTP POST request to the `/payment/api/editable/update` endpoint.
2.  The request contains malicious PHP code within the POST parameters, designed for remote code execution.
3.  The vulnerable endpoint uses `file_put_contents()` to write the attacker-supplied PHP code directly into an existing PHP file, overwriting its original content.
4.  The overwritten PHP file is located within the payment processing directory.
5.  During normal payment processing, the application uses `require()` to include and execute the modified PHP file.
6.  The attacker's malicious PHP code is executed on the server with the permissions of the web server user.
7.  The attacker gains control of the server, enabling activities like installing web shells.

## Impact

Successful exploitation of CVE-2026-31843 allows unauthenticated attackers to achieve remote code execution on the affected server. This could lead to complete compromise of the system, potentially affecting sensitive data such as customer payment information, API keys, and other confidential data stored within the Laravel application. The impact is particularly severe for e-commerce platforms and any application processing financial transactions using the vulnerable package.

## Recommendation

*   Upgrade the `goodoneuz/pay-uz` Laravel package to a patched version greater than 2.2.24 to remediate CVE-2026-31843.
*   Monitor web server logs for suspicious POST requests to the `/payment/api/editable/update` endpoint as described in the attack chain.
*   Deploy the Sigma rule `Detect Pay-UZ Laravel RCE Attempt` to identify exploitation attempts via HTTP requests to the vulnerable endpoint.
*   Enable web server logging to capture HTTP POST request data for effective detection and investigation.
