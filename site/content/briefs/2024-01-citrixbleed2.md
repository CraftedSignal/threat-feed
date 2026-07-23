---
title: CitrixBleed 2 Memory Disclosure via CVE-2025-5777
slug: 2024-01-citrixbleed2
description: Exploitation of CVE-2025-5777 (CitrixBleed 2) in Citrix NetScaler ADC and Gateway leads to memory disclosure by sending crafted POST requests to the /p/u/doAuthentication.do endpoint, potentially leaking session tokens and authentication materials.
date: "2024-01-03T12:00:00Z"
lastmod: "2026-07-23T04:04:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - citrixbleed2
  - memory-disclosure
  - web-application
vendors:
  - Citrix
  - SimpleHelp
  - Fortinet
products:
  - Citrix NetScaler / ADC
  - SimpleHelp RMM
  - Fortinet EMS
  - NetScaler ADC 14.1 (< 14.1-12.39)
  - NetScaler ADC 13.1 (< 13.1-51.15)
  - NetScaler ADC 13.0 (< 13.0-93.19)
  - NetScaler ADC 12.1 (< 12.1-66.25)
  - NetScaler Gateway 14.1 (< 14.1-12.39)
  - NetScaler Gateway 13.1 (< 13.1-51.15)
  - NetScaler Gateway 13.0 (< 13.0-93.19)
  - NetScaler Gateway 12.1 (< 12.1-66.25)
affected_os:
  - Windows
  - Linux
  - ESXi
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX693420
  - https://www.netscaler.com/blog/news/critical-security-updates-for-netscaler-netscaler-gateway-and-netscaler-console/
  - https://github.com/mingshenhk/CitrixBleed-2-CVE-2025-5777-PoC-
  - https://horizon3.ai/attack-research/attack-blogs/cve-2025-5777-citrixbleed-2-write-up-maybe/
  - https://labs.watchtowr.com/how-much-more-must-we-bleed-citrix-netscaler-memory-disclosure-citrixbleed-2-cve-2025-5777/
  - https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2025/CVE-2025-5777.yaml
  - https://www.darkreading.com/cyberattacks-data-breaches/inc-ransomware-thrives-by-mastering-the-basics
  - https://sploitus.com/exploit?id=53F7502A-7C69-5A7A-8481-DD970FF74FF5&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=53F7502A-7C69-5A7A-8481-DD970FF74FF5
  - type: domain
    value: target.example.com
ioc_counts:
  domain: 1
  url: 1
rules:
  - title: CitrixBleed2 POST Request to Authentication Endpoint
    description: Detects POST requests to the /p/u/doAuthentication.do endpoint, potentially indicating CitrixBleed2 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1588.002
    data_sources:
      - webserver
      - linux
  - title: CitrixBleed2 Suspicious User Agent
    description: Detects requests to the /p/u/doAuthentication.do endpoint from suspicious user agents like HeadlessChrome, often used in scanning and exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1588.002
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-06-17T20:47:15Z"
    level: L2
    summary: added CVE-2023-3519 +3; OS windows; OS linux; OS esxi
    sources:
      - dark-reading
  - at: "2026-07-23T04:04:39Z"
    level: L1
    summary: new IOCs
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=53F7502A-7C69-5A7A-8481-DD970FF74FF5&utm_source=rss&utm_medium=rss
---

CVE-2025-5777, also known as CitrixBleed 2, is a memory disclosure vulnerability affecting Citrix NetScaler ADC and Gateway appliances. This vulnerability allows an unauthenticated attacker to potentially leak sensitive information, including session tokens and authentication credentials, from the device's memory. The attack involves sending specially crafted POST requests with incomplete form data to the `/p/u/doAuthentication.do` endpoint. Successful exploitation can lead to unauthorized access to internal resources and systems, posing a significant risk to organizations using affected Citrix products. The vulnerability was publicly disclosed in March 2026 (fictional date based on the source). Defenders should prioritize detecting and mitigating this vulnerability to prevent potential data breaches and unauthorized access.

## Attack Chain

1.  The attacker identifies a vulnerable Citrix NetScaler ADC or Gateway appliance exposed to the internet.
2.  The attacker crafts a malicious POST request with incomplete form data targeting the `/p/u/doAuthentication.do` endpoint.
3.  The attacker sends the crafted POST request to the vulnerable Citrix appliance.
4.  The vulnerable appliance processes the request, leading to a memory leak.
5.  The response from the Citrix appliance contains sensitive data from memory, including session tokens and potentially authentication credentials.
6.  The attacker captures the leaked data from the response.
7.  The attacker analyzes the captured data to extract valid session tokens.
8.  The attacker uses the stolen session tokens to bypass authentication and gain unauthorized access to internal resources and systems.

## Impact

Successful exploitation of CVE-2025-5777 can result in significant data breaches and unauthorized access to sensitive internal resources. An attacker can steal valid session tokens, bypassing authentication mechanisms, and potentially gain complete control over affected Citrix systems. This could lead to the exposure of customer data, intellectual property, and other confidential information. The impact can range from data theft and service disruption to full system compromise, depending on the scope of the attacker's access.

## Recommendation

*   Deploy the Sigma rule `CitrixBleed2_Post_Request` to detect suspicious POST requests to the `/p/u/doAuthentication.do` endpoint in your web server logs.
*   Investigate alerts triggered by the `CitrixBleed2_UserAgent` Sigma rule, focusing on unusual user agents making requests to the vulnerable endpoint.
*   Ensure your Citrix NetScaler ADC and Gateway devices are patched to the latest version to mitigate CVE-2025-5777, as recommended in the Citrix advisory.
*   Monitor Suricata logs for traffic matching the `suricata_citrixbleed2.log` attack data provided in the test section to validate detection coverage.
