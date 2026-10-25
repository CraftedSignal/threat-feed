---
brief_id: brief-2024-01-26-f5-tmui-auth-bypass
event_id: brief-2024-01-26-f5-tmui-auth-bypass
revision: 1
activity_at: "2024-01-26T18:23:00Z"
title: F5 BIG-IP TMUI Authentication Bypass via CVE-2023-46747
slug: 2024-01-f5-tmui-auth-bypass
description: Exploitation of CVE-2023-46747, an authentication bypass vulnerability in F5 BIG-IP's Traffic Management User Interface (TMUI), allows unauthorized access and potentially leads to remote code execution.
date: "2024-01-26T18:23:00Z"
lastmod: "2026-10-25T19:47:36Z"
type: threat
types:
  - threat
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:f5:big-ip_access_policy_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_advanced_firewall_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_advanced_web_application_firewall:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_carrier-grade_nat:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_ddos_hybrid_defender:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_ssl_orchestrator:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_domain_name_system:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_local_traffic_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_policy_enforcement_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_automation_toolchain:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_container_ingress_services:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_application_security_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_analytics:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_application_acceleration_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_application_visibility_and_reporting:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_fraud_protection_services:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_global_traffic_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_link_controller:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_webaccelerator:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_websafe:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FU2X2000-CVE-2023-46747&utm_source=rss&utm_medium=rss
tags:
  - f5
  - big-ip
  - tmui
  - authentication-bypass
  - cve-2023-46747
  - webserver
vendors:
  - F5
products:
  - BIG-IP Access Policy Manager (<= 13.1.5, 14.1.5, 15.1.10, 16.1.4, 17.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2023-46747
    cvss: 9.8
    epss: 0.96515
    kev_status: "false"
references:
  - https://www.praetorian.com/blog/refresh-compromising-f5-big-ip-with-request-smuggling-cve-2023-46747/
  - https://github.com/projectdiscovery/nuclei-templates/blob/3b0bb71bd627c6c3139e1d06c866f8402aa228ae/http/cves/2023/CVE-2023-46747.yaml
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FU2X2000-CVE-2023-46747&utm_source=rss&utm_medium=rss
rules:
  - title: F5 TMUI Authentication Bypass
    description: Detects attempts to exploit CVE-2023-46747, an authentication bypass vulnerability in F5 BIG-IP TMUI by monitoring for PATCH requests to specific URI paths.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: F5 TMUI Auth Bypass - Suspicious User Agent
    description: Detects potential F5 TMUI Authentication Bypass attempts by identifying suspicious user agents.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-10-25T19:47:36Z"
    level: L2
    summary: poc_available; added CVE-2023-46747
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-FU2X2000-CVE-2023-46747&utm_source=rss&utm_medium=rss
---

CVE-2023-46747 is a critical authentication bypass vulnerability affecting F5 BIG-IP's Traffic Management User Interface (TMUI). This vulnerability allows a remote attacker to bypass authentication and gain unauthorized access to the BIG-IP system. Successful exploitation can lead to remote code execution, data theft, and complete system compromise. The vulnerability exists because of an undisclosed flaw in the TMUI that allows specially crafted HTTP requests to bypass authentication checks. Praetorian reported active exploitation in the wild.

## Attack Chain

1.  The attacker identifies a vulnerable F5 BIG-IP instance with TMUI enabled.
2.  The attacker sends a crafted HTTP PATCH request to the `/mgmt/tm/auth/user/` endpoint.
3.  The crafted request bypasses authentication checks due to the vulnerability in TMUI.
4.  The system incorrectly grants the attacker access as an authenticated user.
5.  The attacker leverages the unauthorized access to execute arbitrary commands on the system.
6.  The attacker may install a web shell or other persistent backdoor for continued access.
7.  The attacker escalates privileges to gain root access.
8.  The attacker exfiltrates sensitive data, disrupts services, or performs other malicious activities.

## Impact

Successful exploitation of CVE-2023-46747 can have severe consequences. An attacker can gain complete control over the F5 BIG-IP system, leading to disruption of critical services, data breaches, and financial losses. Given that F5 BIG-IP devices are often used in large enterprise networks, a successful attack could have a widespread impact, affecting numerous users and applications.

## Recommendation

*   Deploy the Sigma rule `F5 TMUI Authentication Bypass` to your SIEM and tune for your environment, focusing on web server logs.
*   Immediately patch CVE-2023-46747 on all affected F5 BIG-IP systems (reference: F5 security advisory).
*   Monitor web server logs for PATCH requests to the `/mgmt/tm/auth/user/` URI path, as highlighted in the Sigma rule.
*   Inspect web traffic for unusual HTTP user agents associated with CVE-2023-46747 exploitation.
