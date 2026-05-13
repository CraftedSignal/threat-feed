---
title: 'CVE-2026-42945: NGINX ngx_http_rewrite_module Heap Buffer Overflow'
slug: 2026-05-nginx-heap-overflow
description: NGINX Plus and NGINX Open Source are vulnerable to a heap buffer overflow (CVE-2026-42945) due to crafted HTTP requests when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed PCRE capture with a replacement string that includes a question mark, potentially leading to denial of service or code execution.
date: "2026-05-13T16:26:37Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - cve
  - CVE-2026-42945
  - nginx
  - heap overflow
  - denial of service
  - webserver
vendors:
  - NGINX
products:
  - NGINX Plus
  - NGINX Open Source
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: 'Endpoint Denial of Service: Application Exhaustion'
cves:
  - id: CVE-2026-42945
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42945
rules:
  - title: Detects CVE-2026-42945 Exploitation — HTTP Request with Question Mark in URI and Rewrite Module
    description: Detects CVE-2026-42945 exploitation — HTTP requests with a question mark and URI targeting rewrite rules.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-42945 Exploitation — HTTP Request with Question Mark in Query and Rewrite Module
    description: Detects CVE-2026-42945 exploitation — HTTP requests with a question mark in the query string and URI targeting rewrite rules.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

NGINX Plus and NGINX Open Source are susceptible to a heap buffer overflow vulnerability (CVE-2026-42945) within the `ngx_http_rewrite_module`. This flaw arises when the `rewrite` directive is used in conjunction with a subsequent `rewrite`, `if`, or `set` directive, and an unnamed Perl-Compatible Regular Expression (PCRE) capture (e.g., `$1`, `$2`) includes a question mark (`?`) within its replacement string. An unauthenticated attacker, by sending specially crafted HTTP requests, can exploit this condition. Successful exploitation can lead to a heap buffer overflow in the NGINX worker process, resulting in a restart and potential denial of service. On systems where Address Space Layout Randomization (ASLR) is disabled, successful exploitation may lead to arbitrary code execution.

## Attack Chain

1.  The attacker crafts a malicious HTTP request targeting a vulnerable NGINX server. This request is designed to trigger the flawed rewrite logic.
2.  The request contains a specific URI or header that will be processed by the `ngx_http_rewrite_module`.
3.  The NGINX configuration utilizes the `rewrite` directive followed by either `rewrite`, `if`, or `set`.
4.  The `rewrite` directive uses an unnamed PCRE capture (e.g., $1, $2) with a replacement string.
5.  The replacement string within the PCRE capture includes a question mark (`?`). This is a crucial component of the exploit.
6.  When the NGINX worker processes the crafted request and applies the rewrite rules, the question mark within the PCRE capture's replacement string causes a heap buffer overflow.
7.  The heap buffer overflow corrupts memory within the NGINX worker process.
8.  The corruption leads to a crash of the NGINX worker process, causing a restart and potential denial of service. On systems with ASLR disabled, the attacker might achieve code execution.

## Impact

Successful exploitation of CVE-2026-42945 can lead to a denial-of-service condition, as the NGINX worker process crashes and restarts. This can disrupt web services and applications served by the affected NGINX instance. In scenarios where ASLR is disabled, the attacker could potentially achieve arbitrary code execution on the server, leading to complete system compromise. The number of affected systems depends on the prevalence of vulnerable NGINX configurations.

## Recommendation

*   Apply the official patch or upgrade to a version of NGINX Plus or NGINX Open Source that addresses CVE-2026-42945.
*   Deploy the Sigma rules provided to detect exploitation attempts targeting CVE-2026-42945 in your NGINX webserver logs.
*   Enable Address Space Layout Randomization (ASLR) on systems running NGINX to mitigate potential code execution following a heap overflow.
*   Review NGINX configurations for instances of the `rewrite` directive used in conjunction with `rewrite`, `if`, or `set` and unnamed PCRE captures containing question marks (`?`).
