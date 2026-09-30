---
title: Active Exploitation of Cisco Catalyst SD-WAN Manager Authentication Bypass (CVE-2026-76504)
slug: 2026-09-cisco-sdwan-auth-bypass
description: Attackers are actively exploiting an unauthenticated API authentication bypass vulnerability (CVE-2026-76504) in Cisco Catalyst SD-WAN Manager to gain administrative control via URL-encoded HTTP requests.
date: "2026-09-30T16:33:07Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:cisco:catalyst_sd-wan_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:catalyst_sd-wan_manager:20.12.6:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vbond_orchestrator:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vbond_orchestrator:20.12.6:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vsmart_controller:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vsmart_controller:20.12.6:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:catalyst_sd-wan_manager:20.12.7:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vbond_orchestrator:20.12.7:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:sd-wan_vsmart_controller:20.12.7:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cisco
  - sdwan
  - authentication-bypass
vendors:
  - Cisco
products:
  - Catalyst SD-WAN Manager (earlier than 20.9.10.1, 20.9 to 20.12.8.2, 20.12 to 20.15.6.1, 20.15 to 20.18.4.1, 20.18 to 26.1.2.1, 26.1 to 26.2.1)
  - Cisco SD-WAN Cloud (< 20.15.605)
cves:
  - id: CVE-2026-76504
    cvss: 9.8
  - id: CVE-2026-20127
    cvss: 10
    epss: 0.88476
  - id: CVE-2026-20182
    cvss: 10
    epss: 0.91522
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-webauth-xr8beuuU
  - https://www.rapid7.com/blog/post/etr-critical-cisco-catalyst-sd-wan-manager-api-authentication-bypass-exploited-in-the-wild-cve-2026-76504
---

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
