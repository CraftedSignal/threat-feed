---
brief_id: brief-2024-10-26-ivanti-epm-sqli
event_id: brief-2024-10-26-ivanti-epm-sqli
revision: 1
activity_at: "2024-10-26T12:00:00Z"
title: Ivanti EPM SQL Injection Vulnerability Exploitation (CVE-2024-29824)
slug: 2024-10-ivanti-epm-sqli
description: Exploitation of CVE-2024-29824, a critical SQL injection vulnerability in Ivanti Endpoint Manager (EPM), allows remote code execution via a crafted HTTP POST request to the `/WSStatusEvents/EventHandler.asmx` endpoint.
date: "2024-10-26T12:00:00Z"
lastmod: "2026-10-22T08:46:44Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:ivanti:endpoint_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:ivanti:endpoint_manager:2022:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HORIZON3AI-CVE-2024-29824&utm_source=rss&utm_medium=rss
tags:
  - ivanti
  - epm
  - sql-injection
  - remote-code-execution
  - cve-2024-29824
vendors:
  - Ivanti
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2024-29824
    cvss: 8.8
    epss: 0.99938
    kev_status: "false"
references:
  - https://www.horizon3.ai/attack-research/attack-blogs/cve-2024-29824-deep-dive-ivanti-epm-sql-injection-remote-code-execution-vulnerability/
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-29824
  - https://github.com/projectdiscovery/nuclei-templates/pull/10020/files
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HORIZON3AI-CVE-2024-29824&utm_source=rss&utm_medium=rss
rules:
  - title: Ivanti EPM CVE-2024-29824 Exploitation Attempt
    description: Detects potential exploitation attempts of CVE-2024-29824 by monitoring HTTP POST requests to the /WSStatusEvents/EventHandler.asmx endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
  - title: Ivanti EPM CVE-2024-29824 Suspicious User Agent
    description: Detects potential exploitation attempts of CVE-2024-29824 using suspicious user agents often associated with automated exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
rules_count: 2
updates:
  - at: "2026-10-22T08:46:44Z"
    level: L2
    summary: poc_available; added CVE-2024-29824
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HORIZON3AI-CVE-2024-29824&utm_source=rss&utm_medium=rss
---

CVE-2024-29824 is a critical SQL injection vulnerability affecting Ivanti Endpoint Manager (EPM). The vulnerability, which has a CVSS score of 9.8, resides in the `RecordGoodApp` function within the `PatchBiz.dll` file. Successful exploitation allows an unauthenticated attacker to execute arbitrary code remotely on the target system. Publicly available exploit code exists, increasing the likelihood of widespread exploitation. The vulnerability can be exploited by crafting a malicious HTTP POST request targeting the `/WSStatusEvents/EventHandler.asmx` endpoint, specifically manipulating the `goodApp.md5` parameter. This vulnerability poses a significant risk to organizations utilizing vulnerable versions of Ivanti EPM.

## Attack Chain

1.  The attacker identifies a vulnerable Ivanti EPM server exposed to the network.
2.  The attacker crafts a malicious HTTP POST request targeting the `/WSStatusEvents/EventHandler.asmx` endpoint.
3.  The crafted POST request includes a SQL injection payload within the `goodApp.md5` parameter.
4.  The vulnerable `RecordGoodApp` function in `PatchBiz.dll` processes the malicious SQL query without proper sanitization.
5.  The injected SQL code executes arbitrary commands on the underlying database server, potentially using `xp_cmdshell`.
6.  The attacker gains remote code execution on the Ivanti EPM server, allowing them to install malware or exfiltrate data.
7.  The attacker establishes persistence mechanisms for continued access.
8.  The attacker pivots to other systems within the network, escalating privileges and achieving further objectives.

## Impact

Successful exploitation of CVE-2024-29824 allows for complete compromise of the Ivanti EPM server. This can lead to data breaches, system outages, and the deployment of ransomware. Given the critical role of EPM in managing endpoints, a successful attack can cascade to compromise numerous other systems within the organization. The vulnerability's high CVSS score (9.8) reflects the severity of the potential impact.

## Recommendation

*   Deploy the Sigma rule `Ivanti EPM CVE-2024-29824 Exploitation Attempt` to detect suspicious HTTP requests to the `/WSStatusEvents/EventHandler.asmx` endpoint (logsource: webserver).
*   Enable TLS inspection on web traffic to inspect the content of HTTP POST requests and detect malicious SQL payloads (logsource: proxy).
*   Review and restrict access to the `/WSStatusEvents/EventHandler.asmx` endpoint to only authorized users or systems (firewall logs).
*   Prioritize patching Ivanti EPM to the latest version to remediate CVE-2024-29824, as documented in Ivanti's security advisory (reference: CVE-2024-29824).
