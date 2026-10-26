---
brief_id: brief-2026-05-06-redis-rce
event_id: brief-2026-05-06-redis-rce
revision: 2
activity_at: "2026-10-26T20:05:14Z"
revision_history:
  - revision: 2
    at: "2026-10-26T20:05:14Z"
    checksum: sha256:45d9ec17e1641f36065a32ef85edbbde400dcd1dcf5542eb6c97040830b5097d
    summary: redis version < 8.6.3
    changed_fields:
      - affected_os
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - iocs
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KS:EXPLOITS-LINUX-REDIS-VALKEY_CVE_2026_25243_RCE&utm_source=rss&utm_medium=rss
title: Multiple Vulnerabilities in Redis Allow Remote Code Execution
slug: 2026-05-redis-rce
description: Multiple vulnerabilities in Redis could allow an attacker to execute arbitrary code remotely, potentially leading to complete system compromise.
date: "2026-05-06T00:00:00Z"
lastmod: "2026-10-26T20:04:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*
tags:
  - redis
  - rce
  - vulnerability
vendors:
  - Redis
  - Cisco
  - Microsoft
products:
  - Redis (< 8.6.3)
  - Cisco Unified Communications Manager
  - Cisco Unified Communications Manager Session Management Edition
  - Microsoft Edge Stable Channel (< 149.0.4022.62)
  - Cisco Unified Communications Manager Release 14 < 14SU6
  - Cisco Unified Communications Manager Release 15 < 15SU5
  - Cisco Unified Communications Manager Session Management Edition Release 14 < 14SU6
  - Cisco Unified Communications Manager Session Management Edition Release 15 < 15SU5
  - Unified Communications Manager
  - Unified Communications Manager Session Management Edition
  - Cisco Unified CM
  - Cisco Unified CM SME
  - Unified Communications Manager < 14SU6
  - Unified Communications Manager Session Management Edition < 14SU6
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2026-23479
    cvss: 8.8
    epss: 0.01659
    kev_status: "false"
  - id: CVE-2026-23631
    cvss: 8.1
    epss: 0.03088
    kev_status: "false"
  - id: CVE-2026-25243
    cvss: 8.8
    epss: 0.04033
    kev_status: "false"
  - id: CVE-2026-20253
    kev_status: unknown
  - id: CVE-2026-20230
    kev_status: unknown
  - id: CVE-2026-20251
    kev_status: unknown
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0536/
  - https://github.com/redis/redis/security/advisories/GHSA-8ghh-qpmp-7826
  - https://github.com/redis/redis/security/advisories/GHSA-93m2-935m-8rj3
  - https://github.com/redis/redis/security/advisories/GHSA-c8h9-259x-jff4
  - https://www.cve.org/CVERecord?id=CVE-2026-23479
  - https://www.cve.org/CVERecord?id=CVE-2026-23631
  - https://www.cve.org/CVERecord?id=CVE-2026-25243
  - https://thehackernews.com/2026/06/critical-splunk-enterprise-flaw-lets.html
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-ssrf-cXPnHcW?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Unified%20Communications%20Manager%20Server-Side%20Request%20Forgery%20Vulnerability%26vs_k=1
  - https://cyber.gc.ca/en/alerts-advisories/microsoft-edge-security-advisory-av26-591
  - https://cyber.gc.ca/en/alerts-advisories/cisco-security-advisory-av26-547
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20253
  - https://www.cisa.gov/news-events/alerts/2026/06/18/cisa-adds-one-known-exploited-vulnerability-catalog
  - https://ccb.belgium.be/advisories/warning-actively-exploited-critical-vulnerability-splunk-enterprise-can-lead-remote-code
  - https://www.cve.org/CVERecord?id=CVE-2026-20230
  - https://www.darkreading.com/cyberattacks-data-breaches/less-than-24-hours-attackers-weaponize-cisco-cucm-flaw
  - https://sploitus.com/exploit?id=030DAD67-A828-5EBE-BC28-DC3BB6C406CE&utm_source=rss&utm_medium=rss
  - https://www.securityweek.com/cisco-confirms-in-the-wild-exploitation-of-unified-cm-vulnerability/
  - https://github.com/elastic/detection-rules/blob/main/rules/network/initial_access_splunk_postgres_backup_restore_rce_sequence.toml
  - https://sploitus.com/exploit?id=KS:EXPLOITS-LINUX-REDIS-VALKEY_CVE_2026_25243_RCE&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=030DAD67-A828-5EBE-BC28-DC3BB6C406CE&utm_source=rss&utm_medium=rss
  - type: url
    value: https://sploitus.com/exploit?id=030DAD67-A828-5EBE-BC28-DC3BB6C406CE
ioc_counts:
  url: 2
rules:
  - title: Detect Suspicious Redis Activity
    description: Detects suspicious network activity related to Redis exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - network_connection
      - linux
  - title: Detect Redis Configuration File Modification
    description: Detects modification of Redis configuration file by attacker
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
updates:
  - at: "2026-06-25T22:18:01Z"
    level: L1
    summary: new product
    sources:
      - dark-reading
  - at: "2026-06-26T22:02:43Z"
    level: L2
    summary: added CVE-2026-20251;
    sources:
      - sploitus
  - at: "2026-07-02T10:54:26Z"
    level: L1
    summary: new product
    sources:
      - securityweek
  - at: "2026-07-03T15:43:18Z"
    level: L1
    summary: new product
    sources:
      - elastic
  - at: "2026-10-26T20:04:28Z"
    level: L2
    summary: redis version < 8.6.3
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KS:EXPLOITS-LINUX-REDIS-VALKEY_CVE_2026_25243_RCE&utm_source=rss&utm_medium=rss
---

On May 6, 2026, CERT-FR published an advisory regarding multiple vulnerabilities discovered in Redis, a popular in-memory data structure store. These vulnerabilities, detailed in Redis security bulletins GHSA-8ghh-qpmp-7826, GHSA-93m2-935m-8rj3, and GHSA-c8h9-259x-jff4, could allow a remote attacker to execute arbitrary code on a vulnerable system. The vulnerabilities impact all versions of Redis. Successful exploitation could lead to a complete compromise of the Redis server and any data it holds. Defenders should apply patches or workarounds as soon as possible to mitigate the risk.

## Attack Chain

1. The attacker identifies a vulnerable Redis instance exposed to the network.
2. The attacker leverages one of the vulnerabilities (CVE-2026-23479, CVE-2026-23631, or CVE-2026-25243) to inject malicious code.
3. This code could involve crafting a specific request that exploits a buffer overflow or other memory corruption issue in Redis.
4. The injected code is executed within the context of the Redis server process.
5. The attacker gains control of the Redis server process.
6. The attacker uses the compromised Redis server to execute arbitrary system commands.
7. The attacker may install a persistent backdoor for future access.
8. The attacker can then move laterally within the network, compromise other systems, or exfiltrate sensitive data.

## Impact

Successful exploitation of these vulnerabilities in Redis can lead to a complete compromise of the affected system. This could result in data theft, data corruption, or denial of service. Given the widespread use of Redis in various applications and services, a successful attack could have a significant impact on organizations that rely on it. The number of potential victims is substantial, spanning various sectors that utilize Redis for caching, session management, and real-time analytics.

## Recommendation

*   Immediately apply the security patches provided by Redis to address CVE-2026-23479, CVE-2026-23631, and CVE-2026-25243.
*   Monitor network traffic for suspicious activity targeting Redis ports, as indicated by the network connection logs and firewall logs.
*   Implement strict access control policies to limit access to Redis instances, based on network connection logs.
*   Deploy the Sigma rule "Detect Suspicious Redis Activity" to identify potential exploitation attempts.
