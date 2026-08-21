---
title: Multiple Vulnerabilities in VMware Tanzu Spring Security
slug: 2026-08-vmware-tanzu-vulnerabilities
description: Multiple vulnerabilities in VMware Tanzu Spring Security, tracked as CVE-2024-22259 and CVE-2024-22262, allow remote attackers to perform file manipulation, information disclosure, cross-site scripting (XSS), and security control bypass.
date: "2026-08-21T13:14:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:linux:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:vmware_vsphere:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:windows:*:*
tags:
  - vulnerability
  - web-security
vendors:
  - VMware
products:
  - Tanzu Spring Security
cves:
  - id: CVE-2024-22259
    cvss: 8.1
    epss: 0.02573
  - id: CVE-2024-22262
    cvss: 8.1
    epss: 0.01191
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2956
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all systems running Tanzu Spring Security
      owner: IT Operations
      due: 24h
      evidence: Source advisory notification regarding multiple vulnerabilities
  mitigation_plan:
    - priority: immediate
      action: Apply patches for CVE-2024-22259 and CVE-2024-22262
      owner: IT Operations
      addresses: CVE-2024-22259, CVE-2024-22262
      evidence: Advisory requires patching to mitigate risk
---

VMware has identified multiple vulnerabilities within the Tanzu Spring Security framework, specifically addressing CVE-2024-22259 and CVE-2024-22262. These flaws pose a significant risk to applications integrated with this security framework, as they allow unauthenticated or remote attackers to manipulate files, disclose sensitive information, execute cross-site scripting (XSS) attacks, and bypass established security controls. Given the nature of these vulnerabilities, they facilitate a range of unauthorized actions that could compromise the integrity and confidentiality of the host application and its underlying data. Organizations using Tanzu Spring Security should review the advisory to determine the impact on their specific deployments and prioritize applying necessary patches or security updates to mitigate the risks associated with these CVEs.

## Impact

Successful exploitation of these vulnerabilities allows for unauthorized access to application data, the potential for persistent XSS attacks affecting end-users, and the compromise of security mechanisms. The scope of impact includes any infrastructure, such as cloud-native environments or on-premises servers, that relies on the Tanzu Spring Security framework for authentication and authorization logic.

## Recommendation

Prioritize the identification of all instances of VMware Tanzu Spring Security within the production environment to assess vulnerability exposure. Once identified, apply the security patches provided by VMware for CVE-2024-22259 and CVE-2024-22262 immediately to prevent exploitation of the security control bypass and information disclosure vectors. Ensure that internal web application firewalls are configured to inspect traffic for typical XSS payloads until patches can be fully verified.
