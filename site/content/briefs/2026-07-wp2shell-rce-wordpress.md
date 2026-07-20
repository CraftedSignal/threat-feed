---
title: 'CVE-2026-63030: Critical Remote Code Execution Vulnerability in WordPress Core'
slug: 2026-07-wp2shell-rce-wordpress
description: CVE-2026-63030 is a critical unauthenticated remote code execution vulnerability affecting WordPress Core versions 6.9.0 through 6.9.4 and 7.0.0 through 7.0.1, allowing an unauthenticated attacker to execute arbitrary code via the WordPress REST API batch endpoint, potentially leading to complete website compromise.
date: "2026-07-17T22:47:35Z"
lastmod: "2026-07-20T13:56:37Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:o:sonicwall:sma6210_firmware:12.4.3-03245:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma6210_firmware:12.4.3-03387:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma6210_firmware:12.4.3-03434:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma6210_firmware:12.5.0-02283:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma6210_firmware:12.5.0-02624:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma6210_firmware:12.5.0-02800:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma7210_firmware:12.4.3-03245:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma7210_firmware:12.4.3-03387:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma7210_firmware:12.4.3-03434:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma7210_firmware:12.5.0-02283:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma7210_firmware:12.5.0-02624:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sma7210_firmware:12.5.0-02800:*:*:*:*:*:*:*
  - cpe:2.3:a:sonicwall:sma8200v:12.4.3-03245:*:*:*:*:*:*:*
  - cpe:2.3:a:sonicwall:sma8200v:12.4.3-03387:*:*:*:*:*:*:*
  - cpe:2.3:a:sonicwall:sma8200v:12.4.3-03434:*:*:*:*:*:*:*
  - cpe:2.3:a:sonicwall:sma8200v:12.5.0-02283:*:*:*:*:*:*:*
  - cpe:2.3:a:sonicwall:sma8200v:12.5.0-02624:*:*:*:*:*:*:*
  - cpe:2.3:a:sonicwall:sma8200v:12.5.0-02800:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:subscription:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:2016:*:*:*:enterprise:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:2019:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*
  - cpe:2.3:a:digitalbazaar:forge:*:*:*:*:*:node.js:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=1BE287ED-2D37-54AE-B8E7-515C18143FB2&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - rce
  - web-vulnerability
  - cve
vendors:
  - WordPress
  - SonicWall
  - OpenSSL
  - Microsoft
  - Zoom
  - SAP
  - RabbitMQ
  - n8n
  - Monsta FTP
  - Digital Bazaar
  - ServiceNow
  - F5
  - Splunk
  - Tenable
  - ESET
  - Tanium
  - SGLang
  - 7-Zip
  - Apache
  - AnyDesk
  - Kyverno
  - Trezor
  - Ledger
  - AWS
  - ComfyUI
  - Ollama
  - Open WebUI
  - Langflow
  - Gradio
  - Reliance Infra
products:
  - WordPress Core 6.9.0
  - WordPress Core 6.9.1
  - WordPress Core 6.9.2
  - WordPress Core 6.9.3
  - WordPress Core 6.9.4
  - WordPress Core 7.0.0
  - WordPress Core 7.0.1
  - WordPress (6.8.0 – 6.8.5)
  - WordPress (6.9.0 – 6.9.4)
  - WordPress (7.0.0 – 7.0.1)
  - WordPress (< 6.9.5)
  - WordPress (< 7.0.2)
  - WordPress Core
  - SonicWall Secure Mobile Access (SMA) 1000 series VPN appliances
  - OpenSSL (< 4.0.1)
  - OpenSSL (< 3.6.3)
  - OpenSSL (< 3.5.7)
  - OpenSSL (< 3.4.6)
  - OpenSSL (< 3.0.21)
  - SharePoint Server
  - Active Directory Federation Services
  - Zoom Desktop Client for Windows
  - Zoom VDI Client for Windows
  - SAP
  - RabbitMQ
  - n8n
  - Monsta FTP
  - tdeio64.sys driver
  - node-forge
  - AI Platform
  - NGINX Plus
  - NGINX Open Source
  - Splunk Enterprise
  - Tenable Agent
  - Inspect Connector
  - Tanium Server
  - HTTP/2 server implementations
  - SGLang
  - 7-Zip
  - Apache Tomcat
  - AnyDesk
  - Kyverno
  - Trezor Suite
  - Ledger Wallet
  - Ledger Live
  - ComfyUI
  - Ollama
  - Open WebUI
  - Langflow
  - Gradio
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: reportedly allows an unauthenticated attacker to execute code via the WordPress REST API batch endpoint
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: allows an unauthenticated attacker to execute code via the WordPress REST API batch endpoint
    confidence_band: high
cves:
  - id: CVE-2026-63030
    cvss: 9.8
    epss: 0.08946
  - id: CVE-2026-60137
    cvss: 5.9
    epss: 0.04026
  - id: CVE-2026-15409
    cvss: 10
    epss: 0.01404
  - id: CVE-2026-15410
    cvss: 7.2
    epss: 0.01647
  - id: CVE-2026-56164
    cvss: 5.3
    epss: 0.05601
  - id: CVE-2026-56155
    cvss: 7.8
    epss: 0.00379
  - id: CVE-2026-14960
  - id: CVE-2026-14961
  - id: CVE-2026-33894
    cvss: 7.5
    epss: 0.00339
  - id: CVE-2026-42533
    cvss: 8.1
    epss: 0.0083
  - id: CVE-2026-60005
    cvss: 8.2
    epss: 0.0061
  - id: CVE-2026-56434
    cvss: 6.5
    epss: 0.00387
  - id: CVE-2026-20296
    cvss: 8.3
  - id: CVE-2026-20297
    cvss: 7.2
  - id: CVE-2026-15265
    cvss: 9.1
    epss: 0.00365
references:
  - https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core
  - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63030
  - https://wordpress.org/news/2026/07/wordpress-7-0-2-release/
  - https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/
  - https://blog.cloudflare.com/wordpress-vulnerabilities/
  - https://sploitus.com/exploit?id=1BE287ED-2D37-54AE-B8E7-515C18143FB2&utm_source=rss&utm_medium=rss
  - https://www.securityweek.com/wp2shell-wordpress-vulnerabilities-exploited-in-the-wild/
  - https://thehackernews.com/2026/07/weekly-recap-wordpress-rce-sonicwall-0.html
iocs:
  - type: file_path
    value: .ssh/authorized_keys
  - type: file_path
    value: /dev/shm/.a
  - type: file_path
    value: /var/tmp/.a
  - type: file_path
    value: /tmp/.a
  - type: file_path
    value: /etc/cron.d/.sys_monitor
  - type: file_path
    value: /etc/cron.d/.s
  - type: organization
    value: Kudankulam Nuclear Power Plant
  - type: organization
    value: Reliance Infra (RPOWER)
ioc_counts:
  file_path: 6
  organization: 2
updates:
  - at: "2026-07-19T15:00:33Z"
    level: L2
    summary: poc_available; added CVE-2026-60137
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=1BE287ED-2D37-54AE-B8E7-515C18143FB2&utm_source=rss&utm_medium=rss
  - at: "2026-07-20T05:22:22Z"
    level: L1
    summary: new product
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/wp2shell-wordpress-vulnerabilities-exploited-in-the-wild/
  - at: "2026-07-20T13:56:37Z"
    level: L2
    summary: added CVE-2026-14960 +12; OS windows; OS linux
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/weekly-recap-wordpress-rce-sonicwall-0.html
---

On July 17, 2026, a GitHub Security Advisory was published detailing CVE-2026-63030, a critical unauthenticated remote code execution vulnerability in WordPress Core. This flaw affects WordPress versions 6.9.0 through 6.9.4 and 7.0.0 through 7.0.1. The vulnerability allows an unauthenticated attacker to execute arbitrary code by exploiting the WordPress REST API batch endpoint, specifically when a persistent object cache is not in use. This could lead to a complete compromise of the website and its underlying data without requiring any valid account or user interaction. While the vulnerability has a CVSS score of 7.5, its unauthenticated nature and widespread deployment of WordPress elevate its criticality. The issue is fixed in WordPress 6.9.5 and 7.0.2. At the time of publication, no publicly confirmed in-the-wild exploitation has been observed, but given WordPress's open-source nature and the potential for AI analysis, public proof-of-concept exploits are highly anticipated.

## Attack Chain

1. **Reconnaissance**: An attacker identifies public-facing WordPress instances using web scanning tools or open-source intelligence.
2. **Vulnerability Identification**: The attacker determines that the target WordPress instance is running a vulnerable version (6.9.0-6.9.4 or 7.0.0-7.0.1) and that a persistent object cache, which could mitigate the exploit, is not in use.
3. **Payload Crafting**: The attacker crafts a malicious HTTP POST request, embedding arbitrary code within a specially formatted batch request to the WordPress REST API batch endpoint (e.g., `/wp-json/batch/v1`).
4. **Initial Access**: The crafted request is sent to the vulnerable WordPress server, targeting the REST API batch endpoint.
5. **Code Execution**: The WordPress core, due to CVE-2026-63030, improperly processes the batch request, leading to the execution of the attacker's arbitrary code on the server, exploiting the vulnerable code path enabled by the absence of a persistent object cache.
6. **Persistence and Privilege Escalation**: The executed code establishes persistence (e.g., dropping a webshell, creating new administrator accounts, modifying WordPress core files) and may attempt to escalate privileges on the underlying host operating system.
7. **Impact**: The attacker gains full control over the WordPress instance and potentially the server, enabling actions such as data exfiltration, website defacement, or using the compromised server as a platform for further attacks.

## Impact

Successful exploitation of CVE-2026-63030 grants an unauthenticated attacker remote code execution capabilities on the vulnerable WordPress server. This directly leads to the complete compromise of the website, its content, and any associated databases. Given that WordPress is the most widely used content management system globally, a large number of public-facing websites are potentially at risk. The impact extends to potential data breaches, website defacement, server-side resource abuse (e.g., for cryptocurrency mining or hosting malicious content), and further lateral movement within an organization's network if the WordPress server has access to internal systems.

## Recommendation

* Immediately upgrade all affected WordPress installations to version **6.9.5** or **7.0.2** (or 7.1 Beta 2 for the beta branch) to remediate **CVE-2026-63030**.
* Verify that automatic updates for WordPress are active and have successfully applied the necessary patches to all internet-facing instances.
* Review web server access logs for suspicious POST requests to WordPress REST API batch endpoints (e.g., paths containing `/wp-json/batch/v1`) from unknown or unusual IP addresses, especially around the vulnerability disclosure date.
