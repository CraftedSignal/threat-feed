---
title: Critical Vulnerabilities in Citrix NetScaler ADC and Gateway
slug: 2026-08-citrix-netscaler-vulnerabilities
description: Citrix has released patches for critical vulnerabilities including CVE-2026-19490, an authentication bypass, and CVE-2026-19489, a memory overflow vulnerability affecting NetScaler ADC and Gateway appliances.
date: "2026-08-19T16:34:49Z"
lastmod: "2026-08-20T13:12:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - network-infrastructure
  - authentication-bypass
vendors:
  - Citrix
products:
  - NetScaler ADC (13.1, 14.1)
  - NetScaler Gateway (13.1, 14.1)
  - NetScaler ADC
  - NetScaler Gateway
cves:
  - id: CVE-2026-19489
  - id: CVE-2026-19490
references:
  - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX696939
  - https://cert.europa.eu/publications/security-advisories/2026-010/
  - https://www.rapid7.com/blog/post/etr-cve-2026-19490-critical-vulnerability-affecting-citrix-netscaler-adc-and-netscaler-gateway
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2927
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch NetScaler ADC and Gateway instances to the secure versions listed
      owner: IT Operations
      due: 24h
      evidence: CERT-EU and Citrix advisory recommendations
  mitigation_plan:
    - priority: immediate
      action: Identify vulnerable configurations via CLI search for 'add lsn group' and 'add authentication samlAction'
      owner: Security Operations
      addresses: CVE-2026-19489, CVE-2026-19490
      evidence: Citrix advisory configuration audit steps
updates:
  - at: "2026-08-20T13:12:01Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2927
---

On August 19, 2026, Citrix disclosed critical vulnerabilities affecting NetScaler ADC and NetScaler Gateway products. The vulnerabilities include CVE-2026-19490, an authentication bypass vulnerability with a CVSS score of 9.3, and CVE-2026-19489, a memory overflow vulnerability with a CVSS score of 8.8. The authentication bypass (CVE-2026-19490) is triggered through an alternate path within the Gateway or AAA virtual server configuration, potentially allowing unauthenticated access to the appliance. The memory overflow (CVE-2026-19489) occurs when SIP ALG is enabled within a Large Scale NAT (LSN) group, which may result in unpredictable system behavior or Denial of Service (DoS). Organizations running these versions should prioritize patching to the identified secure releases immediately.

## Impact

Successful exploitation of CVE-2026-19490 may allow remote unauthenticated attackers to bypass security controls and gain unauthorized access to the NetScaler appliance, potentially compromising internal resources. CVE-2026-19489 risks the availability of network services by causing service crashes or unpredictable behavior. These vulnerabilities affect various versions of NetScaler ADC and Gateway, including FIPS and NDcPP variants, creating significant risk for organizations relying on these appliances for secure remote access and load balancing.

## Recommendation

* Immediately audit current NetScaler configurations for the presence of LSN group SIP ALG settings or Gateway/AAA virtual server configurations using the diagnostic commands provided in the official advisory.
* Update all instances of NetScaler ADC and NetScaler Gateway to the following versions: 14.1-73.32, 13.1-63.21, 14.1-73.32 FIPS, or 13.1-37.277 (for FIPS/NDcPP).
* Monitor NetScaler appliance logs and system health metrics for unexpected service restarts or unauthorized access patterns following the patch deployment.
