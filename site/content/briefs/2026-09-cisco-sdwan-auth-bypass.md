---
brief_id: brief-2026-09-cisco-sdwan-auth-bypass
event_id: brief-2026-09-cisco-sdwan-auth-bypass
revision: 2
activity_at: "2026-11-19T16:15:02Z"
revision_history:
  - revision: 2
    at: "2026-11-19T16:15:02Z"
    checksum: sha256:52d1146463b773fbbee939774ac828036b3871d04b7c2256cfaf7c94020b988d
    summary: exploited:true; KEV CVE-2026-20127; KEV CVE-2026-20182; KEV CVE-2026-76504
    changed_fields:
      - affected_products
      - cpes
      - cves
      - exploitation_evidence
      - lastmod
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Active Exploitation of Cisco Catalyst SD-WAN Manager Authentication Bypass (CVE-2026-76504)
slug: 2026-09-cisco-sdwan-auth-bypass
description: Attackers are actively exploiting an unauthenticated API authentication bypass vulnerability (CVE-2026-76504) in Cisco Catalyst SD-WAN Manager to gain administrative control via URL-encoded HTTP requests.
date: "2026-09-30T16:33:07Z"
lastmod: "2026-11-19T16:14:17Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-02-25T00:00:00Z"
  confidence: high
source_assessment:
  reliability: B
  credibility: "1"
  rating: B1
  likelihood: likely
cpes:
  - cpe:2.3:a:cisco:catalyst_sd-wan_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:catalyst_sd-wan_manager:20.12.6:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:catalyst_sd-wan_manager:20.12.7:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:catalyst_sd-wan_manager:26.2:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vbond_orchestrator:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vbond_orchestrator:20.12.6:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vbond_orchestrator:20.12.7:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vsmart_controller:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vsmart_controller:20.12.6:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vsmart_controller:20.12.7:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cisco
  - sdwan
  - authentication-bypass
vendors:
  - Cisco
products:
  - Catalyst SD-WAN Manager
  - Cisco SD-WAN Cloud
product_versions:
  - product: Cisco SD-WAN Cloud
    range: < 20.15.605
cves:
  - id: CVE-2026-76504
    cvss: 9.8
    epss: 0.01096
    kev: true
    kev_status: "true"
  - id: CVE-2026-20127
    cvss: 10
    epss: 0.88476
    kev: true
    kev_status: "true"
  - id: CVE-2026-20182
    cvss: 10
    epss: 0.91522
    kev: true
    kev_status: "true"
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-webauth-xr8beuuU
  - https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-sd-wan-manager-api-authentication-bypass-exploited-in-the-wild-cve-2026-76504
  - https://www.cisa.gov/news-events/alerts/2026/09/30/cisa-adds-one-known-exploited-vulnerability-catalog
  - https://www.cve.org/CVERecord?id=CVE-2026-76504
  - https://www.cisecurity.org/advisory/a-vulnerability-in-cisco-catalyst-sd-wan-manager-could-allow-for-authentication-bypass_2026-105
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3681
updates:
  - at: "2026-09-30T19:39:20Z"
    level: L2
    summary: added coverage for Catalyst SD-WAN Manager
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/alerts/2026/09/30/cisa-adds-one-known-exploited-vulnerability-catalog
  - at: "2026-11-19T16:14:17Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-20127; KEV CVE-2026-20182; KEV CVE-2026-76504
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Cisco has disclosed a critical authentication bypass vulnerability, identified as CVE-2026-76504, affecting Cisco Catalyst SD-WAN Manager. The flaw stems from improper handling of URL encoding (CWE-177) within API authentication logic. An unauthenticated, remote attacker can leverage this weakness to bypass authentication rules by sending crafted HTTP requests to specific API endpoints, granting them unauthorized access with administrative privileges.

Cisco PSIRT has confirmed that this vulnerability is being actively exploited in the wild as of September 2026. This follows other significant authentication bypass flaws discovered in the Catalyst SD-WAN networking stack earlier in the year (CVE-2026-20127 and CVE-2026-20182). Given the critical nature of the flaw and confirmed in-the-wild exploitation, organizations must treat this as an emergency remediation event. There are no workarounds, and all internet-facing instances are at high risk of compromise. Immediate application of vendor-supplied patches is required to secure the control plane.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing Cisco Catalyst SD-WAN Manager instances.
2. Attacker crafts an HTTP request targeting the j_security_check API endpoint.
3. Attacker applies URI encoding to one or more characters within the request path (e.g., %6a instead of j) to bypass static authentication filters.
4. The SD-WAN Manager improperly processes the encoded URL, incorrectly validating the request as authenticated.
5. Attacker gains session access with the privileges of the admin user.
6. Attacker leverages the administrative session to perform unauthorized configuration changes or exfiltration.
7. Attacker maintains persistence or executes further commands via the compromised management interface.

## Impact

Successful exploitation allows an unauthenticated remote attacker to gain administrative access to the Cisco Catalyst SD-WAN Manager. This impact is severe, potentially resulting in full compromise of the SD-WAN controller, unauthorized access to sensitive network configuration data, or the ability to manipulate global routing and traffic flow across the managed SD-WAN network.

## Recommendation

* Immediately upgrade all on-premises instances of Cisco Catalyst SD-WAN Manager to the fixed releases specified in the Cisco security advisory (e.g., 20.9.10.1, 20.12.8.2, 20.15.6.1, 20.18.4.1, 26.1.2.1, 26.2.1).
* Deploy the Sigma rules below to monitor for exploitation attempts targeting the j_security_check endpoint.
* Audit logs located at /var/log/nms/containers/service-proxy/serviceproxy-access.log and /var/log/nms/vmanage-server.log for indicators of anomalous j_security_check access or unexpected usernames prefixed with 'viptela-reserved-'.
* Restrict access to the SD-WAN management interface to trusted internal IP addresses and protect control components behind network filtering devices.
