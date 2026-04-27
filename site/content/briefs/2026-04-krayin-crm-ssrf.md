---
title: Webkul Krayin CRM SSRF Vulnerability (CVE-2026-38527)
slug: 2026-04-krayin-crm-ssrf
description: A Server-Side Request Forgery (SSRF) vulnerability in Webkul Krayin CRM v2.2.x allows attackers to scan internal resources by sending a crafted POST request to the /settings/webhooks/create endpoint.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-38527
  - ssrf
  - webkul
  - krayin-crm
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
cves:
  - id: CVE-2026-38527
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-38527
  - https://github.com/TREXNEGRO/Security-Advisories/tree/main/CVE-2026-38527
  - https://github.com/krayin/laravel-crm
rules:
  - title: Detect Krayin CRM Webhook SSRF Attempt
    description: Detects potential SSRF exploitation attempts against the /settings/webhooks/create endpoint in Krayin CRM by monitoring POST requests with suspicious URL parameters.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Krayin CRM Webhook SSRF Attempt - Internal IP Range
    description: Detects potential SSRF exploitation attempts by identifying requests containing RFC1918 IP addresses in the Webhook URL.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-38527 details a Server-Side Request Forgery (SSRF) vulnerability affecting Webkul Krayin CRM version 2.2.x. The vulnerability is located in the `/settings/webhooks/create` component. An attacker can exploit this flaw by crafting a malicious POST request that forces the server to make requests to internal resources. This can be leveraged to scan internal network infrastructure, potentially revealing sensitive information or accessing internal services that are not meant to be exposed to…
