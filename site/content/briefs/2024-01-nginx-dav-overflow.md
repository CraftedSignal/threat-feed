---
title: NGINX ngx_http_dav_module Buffer Overflow Vulnerability (CVE-2026-27654)
slug: 2024-01-nginx-dav-overflow
description: A buffer overflow vulnerability (CVE-2026-27654) exists in the ngx_http_dav_module of NGINX Open Source and NGINX Plus, potentially allowing attackers to terminate the NGINX worker process or modify files outside the document root by exploiting specific configurations with MOVE or COPY methods.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - nginx
  - dav
  - buffer-overflow
  - cve-2026-27654
  - denial-of-service
vendors:
  - NGINX
products:
  - NGINX Open Source
  - NGINX Plus
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27654
rules:
  - title: Detect NGINX DAV Module Buffer Overflow Attempt
    description: Detects suspicious HTTP requests potentially exploiting the NGINX ngx_http_dav_module buffer overflow (CVE-2026-27654) based on the presence of DAV methods and potentially oversized parameters.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect NGINX Worker Process Crash
    description: Detects NGINX worker process crashes, which can be an indicator of successful exploitation of CVE-2026-27654, potentially causing a denial-of-service condition.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-27654 describes a buffer overflow vulnerability found within the `ngx_http_dav_module` module in NGINX Open Source and NGINX Plus. This vulnerability can be triggered when the NGINX configuration utilizes the DAV module's MOVE or COPY methods in conjunction with prefix location definitions (non-regular expression location configuration) and alias directives. Successful exploitation of this flaw could allow an attacker to cause the NGINX worker process to terminate, leading to a denial-of-service condition. Additionally, it may be possible to modify source or destination file names outside the intended document root, though the impact is limited by the low privileges typically assigned to the NGINX worker process user. This vulnerability affects systems using vulnerable versions of NGINX Open Source and NGINX Plus with the specified configuration patterns.

## Attack Chain

1. An attacker identifies a vulnerable NGINX server utilizing the `ngx_http_dav_module` with MOVE or COPY methods enabled, along with prefix location configurations and alias directives.
2. The attacker crafts a malicious HTTP request targeting a specific DAV endpoint configured with a prefix location and alias. This request uses either the MOVE or COPY method.
3. The crafted request includes oversized or specially formatted parameters within the HTTP headers or body, designed to trigger a buffer overflow in the `ngx_http_dav_module`'s processing logic.
4. The NGINX worker process receives the malicious request and attempts to process it using the vulnerable code path in the `ngx_http_dav_module`.
5. The buffer overflow occurs during the processing of the MOVE or COPY operation, potentially overwriting adjacent memory regions within the NGINX worker process.
6. Depending on the nature of the overflow, this can lead to one of two outcomes: either the NGINX worker process crashes, resulting in a denial-of-service, or...
7. ...the attacker gains limited control over file operations, potentially modifying file names outside the designated document root by manipulating memory related to file paths.
8. The attacker achieves either denial of service through worker process termination or limited unauthorized file modifications within the constraints of the worker process user's privileges.

## Impact

Successful exploitation of CVE-2026-27654 can result in a denial-of-service condition affecting the targeted NGINX web server. While the integrity impact is constrained due to the low privileges of the NGINX worker process user, attackers may be able to modify file names outside of the intended document root. The number of affected systems depends on the prevalence of NGINX configurations that utilize the vulnerable `ngx_http_dav_module` in conjunction with the specific MOVE/COPY, prefix location, and alias directive patterns. The vulnerability primarily impacts web applications and services reliant on the availability of the NGINX web server.

## Recommendation

*   Upgrade NGINX Open Source and NGINX Plus to a patched version that addresses CVE-2026-27654 (consult the NGINX security advisories).
*   Disable the `ngx_http_dav_module` if it is not required for your web application.
*   If the `ngx_http_dav_module` is necessary, carefully review and restrict the usage of MOVE and COPY methods, prefix locations, and alias directives in your NGINX configuration files.
*   Deploy the Sigma rule "Detect NGINX DAV Module Buffer Overflow Attempt" to your SIEM to identify potential exploitation attempts based on suspicious HTTP requests targeting DAV endpoints.
*   Monitor NGINX worker process stability and resource usage for unexpected crashes or high CPU utilization, which could indicate exploitation attempts.
