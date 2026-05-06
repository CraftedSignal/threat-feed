---
title: NGINX ngx_mail_auth_http_module Denial-of-Service Vulnerability (CVE-2026-27651)
slug: 2026-03-nginx-dos
description: NGINX Plus and NGINX Open Source are vulnerable to a denial-of-service condition (CVE-2026-27651) when the ngx_mail_auth_http_module is enabled, CRAM-MD5 or APOP authentication is used, and the authentication server permits retry via the Auth-Wait response header, leading to worker process termination.
date: "2026-03-24T15:16:32Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - nginx
  - denial-of-service
  - mail proxy
  - cve-2026-27651
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27651
  - https://my.f5.com/manage/s/article/K000160383
rules:
  - title: NGINX Worker Process Termination
    description: Detects sudden NGINX worker process terminations, which may indicate exploitation of CVE-2026-27651.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
  - title: NGINX Auth-Wait Response Header Detection
    description: Detects Auth-Wait headers in responses from authentication servers used by NGINX mail proxy, potentially indicating a vulnerable configuration.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-27651 is a denial-of-service vulnerability affecting NGINX Plus and NGINX Open Source. The vulnerability occurs when the `ngx_mail_auth_http_module` module is enabled, and the server is configured to use CRAM-MD5 or APOP authentication. An attacker can exploit this by sending undisclosed requests that cause worker processes to terminate, leading to a denial-of-service condition. The vulnerability is triggered when the authentication server permits retry by returning the `Auth-Wait`…
