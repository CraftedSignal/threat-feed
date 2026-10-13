---
title: F5 TMUI Remote Code Execution Vulnerability (CVE-2020-5902) Exploitation Attempts
slug: 2026-05-f5-tmui-rce
description: Exploitation attempts targeting F5 BIG-IP, BIG-IQ, and Traffix SDC devices via CVE-2020-5902 are detected through regex pattern matching of exploit strings and directory traversal sequences in syslog data, potentially leading to remote code execution and system compromise.
date: "2026-05-28T17:50:22Z"
lastmod: "2026-10-13T18:47:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:f5:big-ip_access_policy_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_advanced_firewall_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_advanced_web_application_firewall:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_analytics:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_application_acceleration_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_application_security_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_ddos_hybrid_defender:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_domain_name_system:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_fraud_protection_service:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_global_traffic_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_link_controller:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_local_traffic_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_policy_enforcement_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:ssl_orchestrator:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SV3NBEAST-CVE-2020-5902_RCE&utm_source=rss&utm_medium=rss
tags:
  - CVE-2020-5902
  - F5
  - TMUI
  - RCE
  - exploit
  - web
vendors:
  - F5
products:
  - BIG-IP
  - BIG-IQ
  - Traffix SDC
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2020-5902
    cvss: 9.8
    epss: 0.99999
references:
  - https://www.ptsecurity.com/ww-en/about/news/f5-fixes-critical-vulnerability-discovered-by-positive-technologies-in-big-ip-application-delivery-controller/
  - https://support.f5.com/csp/article/K52145254
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SV3NBEAST-CVE-2020-5902_RCE&utm_source=rss&utm_medium=rss
rules:
  - title: Detect F5 TMUI RCE CVE-2020-5902 Exploitation Attempts via Syslog
    description: Detects CVE-2020-5902 exploitation attempts targeting F5 TMUI via syslog based on exploit strings and directory traversal sequences.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - syslog
      - f5
  - title: Detect F5 TMUI RCE CVE-2020-5902 Exploitation Attempts via Web Logs
    description: Detects CVE-2020-5902 exploitation attempts targeting F5 TMUI via web logs based on exploit strings and directory traversal sequences in URI.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-10-13T18:47:43Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SV3NBEAST-CVE-2020-5902_RCE&utm_source=rss&utm_medium=rss
---

This brief focuses on detecting exploitation attempts of CVE-2020-5902, a remote code execution (RCE) vulnerability in the Traffic Management User Interface (TMUI) of F5 BIG-IP, BIG-IQ, and Traffix SDC devices. The vulnerability allows unauthenticated attackers to execute arbitrary commands on the affected devices. Detection relies on identifying specific patterns in syslog data indicative of exploit attempts, including "hsqldb;" and directory traversal sequences ("..;"). Successful exploitation can lead to full system compromise, unauthorized access, data exfiltration, and lateral movement within the network. The exploitation activity is significant because these F5 devices are often critical network infrastructure components.

## Attack Chain

1.  An unauthenticated attacker sends a malicious HTTP request to the TMUI interface of an F5 BIG-IP, BIG-IQ, or Traffix SDC device.
2.  The request contains a crafted URL with directory traversal sequences ("..;") designed to bypass authentication and access restricted resources.
3.  The request includes the "hsqldb;" string, used to exploit a Java deserialization vulnerability within the TMUI.
4.  The vulnerable component processes the malicious request without proper sanitization or validation.
5.  The directory traversal allows the attacker to access and modify sensitive files or execute commands within the context of the TMUI application.
6.  The "hsqldb;" payload triggers the execution of arbitrary Java code, allowing the attacker to gain full control of the system.
7.  The attacker installs a backdoor or establishes a reverse shell to maintain persistent access.
8.  The attacker performs reconnaissance, steals sensitive data, or uses the compromised system as a pivot point for further attacks within the network.

## Impact

Successful exploitation of CVE-2020-5902 allows attackers to execute arbitrary commands on affected F5 devices. This can result in complete system compromise, leading to unauthorized access to sensitive data, data exfiltration, or further lateral movement within the network. Given that F5 devices are often critical network infrastructure components, a successful attack can have a significant impact on the confidentiality, integrity, and availability of network services.

## Recommendation

*   Deploy the Sigma rule "Detect F5 TMUI RCE CVE-2020-5902 Exploitation Attempts via Syslog" to detect exploit attempts based on syslog data.
*   Deploy the Sigma rule "Detect F5 TMUI RCE CVE-2020-5902 Exploitation Attempts via Web Logs" to detect exploit attempts based on web server logs.
*   Ingest logs via syslog from F5 BIG-IP, BIG-IQ, and Traffix SDC devices to ensure coverage, as recommended in the "How to Implement" section.
*   Investigate and remediate any detected exploitation attempts immediately.
*   Refer to F5's advisory (https://support.f5.com/csp/article/K52145254) for patching and mitigation guidance.
