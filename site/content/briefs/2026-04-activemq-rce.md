---
title: Apache ActiveMQ Classic Remote Code Execution Vulnerability (CVE-2026-34197)
slug: 2026-04-activemq-rce
description: A remote code execution (RCE) vulnerability, CVE-2026-34197, exists in Apache ActiveMQ Classic versions before 5.19.4, and all versions from 6.0.0 up to 6.2.3, allowing attackers to execute arbitrary system commands by abusing the Jolokia management API to load external configurations; ActiveMQ has been a repeated target for attackers.
date: "2026-04-08T17:26:40Z"
lastmod: "2026-10-05T16:44:10Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:activemq_broker:*:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:activemq_legacy_openwire_module:*:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:e-series_santricity_unified_manager:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:e-series_santricity_web_services_proxy:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:santricity_storage_plugin:-:*:*:*:*:vcenter:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-CUANH2333-CVE-2023-46604&utm_source=rss&utm_medium=rss
tags:
  - activemq
  - rce
  - vulnerability
  - apache
  - jolokia
  - springxml
vendors:
  - Apache
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Remote File Copy
cves:
  - id: CVE-2026-34197
    cvss: 8.8
    epss: 0.15492
  - id: CVE-2024-32114
    cvss: 8.5
    epss: 0.07148
  - id: CVE-2016-3088
    cvss: 9.8
    epss: 0.98518
  - id: CVE-2023-46604
    cvss: 10
    epss: 0.99891
references:
  - https://www.bleepingcomputer.com/news/security/13-year-old-bug-in-activemq-lets-hackers-remotely-execute-commands/
  - https://horizon3.ai/
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-CUANH2333-CVE-2023-46604&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Suspicious ActiveMQ Broker Configuration via HTTP
    description: Detects attempts to load remote broker configurations via HTTP, indicative of CVE-2026-34197 exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1190
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect ActiveMQ Jolokia API Access without Authentication
    description: Detects access to the ActiveMQ Jolokia API without proper authentication, potentially indicating exploitation of CVE-2024-32114.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-10-05T16:44:10Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-CUANH2333-CVE-2023-46604&utm_source=rss&utm_medium=rss
---

A remote code execution (RCE) vulnerability, tracked as CVE-2026-34197, has been identified in Apache ActiveMQ Classic. This vulnerability, present for 13 years, impacts versions before 5.19.4, and all versions from 6.0.0 up to 6.2.3. Apache ActiveMQ Classic is a widely used open-source message broker written in Java.  The flaw was discovered by Horizon3 researcher Naveen Sunkavally with assistance from the Claude AI assistant. The vulnerability stems from the Jolokia management API, which exposes a broker function that can be abused to load external configurations. Successful exploitation allows attackers to execute arbitrary system commands. Due to ActiveMQ's widespread deployment in enterprise, web backends, government, and company systems, this vulnerability poses a significant risk.

## Attack Chain

1.  Attacker identifies a vulnerable Apache ActiveMQ Classic instance running a vulnerable version (before 5.19.4, or 6.0.0 to 6.2.3).
2.  Attacker authenticates to the Jolokia management API (or bypasses authentication on versions 6.0.0 through 6.1.1 due to CVE-2024-32114).
3.  The attacker crafts a malicious request to the Jolokia API, specifically targeting the `addNetworkConnector` function.
4.  The crafted request forces the ActiveMQ broker to fetch a remote Spring XML configuration file from a URL controlled by the attacker.
5.  The remote Spring XML file contains malicious code or commands.
6.  Upon initialization, the ActiveMQ broker parses the malicious Spring XML file.
7.  The embedded malicious code within the Spring XML file is executed by the ActiveMQ broker process.
8.  The attacker achieves remote code execution on the ActiveMQ server, enabling them to perform actions such as installing malware, exfiltrating data, or disrupting services.

## Impact

Successful exploitation of CVE-2026-34197 allows attackers to execute arbitrary system commands on the ActiveMQ server. This can lead to complete system compromise, data breaches, and service disruption. Given the widespread use of ActiveMQ in enterprise environments, a successful attack could impact numerous organizations and critical infrastructure. Previous ActiveMQ vulnerabilities like CVE-2016-3088 and CVE-2023-46604 have been actively exploited in the wild, highlighting the need for immediate patching and mitigation.

## Recommendation

*   Upgrade Apache ActiveMQ Classic instances to versions 5.19.4 or later, or 6.2.3 or later, to address CVE-2026-34197.
*   For versions 6.0.0 through 6.1.1, ensure that CVE-2024-32114 is patched to prevent unauthenticated access to the Jolokia API.
*   Monitor ActiveMQ broker logs for suspicious connections that use the internal transport protocol `VM` and the `brokerConfig=xbean:http://` query parameter.
*   Deploy the Sigma rule provided to detect exploitation attempts in ActiveMQ logs.
*   Review and harden ActiveMQ access controls to restrict access to the Jolokia management API.
