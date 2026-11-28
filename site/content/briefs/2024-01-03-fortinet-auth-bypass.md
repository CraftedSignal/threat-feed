---
brief_id: brief-2024-01-03-fortinet-auth-bypass
event_id: brief-2024-01-03-fortinet-auth-bypass
revision: 3
activity_at: "2026-11-28T04:33:20Z"
revision_history:
  - revision: 2
    at: "2026-11-20T03:11:01Z"
    checksum: sha256:a981cb4130c29ee5474b49854fdc43893db504dc4a98e46d76b77f2fd530198f
    summary: exploited:true; KEV CVE-2022-40684
    changed_fields:
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - exploitation_evidence
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - revision: 3
    at: "2026-11-28T04:33:20Z"
    checksum: sha256:9b186eb2303850e15c17c410681c4e35fa5235a2f400347d691888e61eeff445
    summary: poc_available
    changed_fields:
      - cve_verification
      - cves
      - exploitation_evidence
      - has_poc
      - lastmod
      - poc_references
      - priority
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KLJUNOWSKY-CVE-2022-40684-POC&utm_source=rss&utm_medium=rss
title: Fortinet Appliance Authentication Bypass Vulnerability (CVE-2022-40684) Exploitation
slug: 2024-01-03-fortinet-auth-bypass
description: Exploitation of CVE-2022-40684, a Fortinet appliance authentication bypass vulnerability, allows unauthorized REST API access to modify system configurations, potentially leading to complete system compromise.
date: "2024-01-03T10:00:00Z"
lastmod: "2026-11-28T04:33:03Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2024-01-03T10:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortiproxy:7.2.0:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortiswitchmanager:7.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortiswitchmanager:7.2.0:*:*:*:*:*:*:*
  - cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KLJUNOWSKY-CVE-2022-40684-POC&utm_source=rss&utm_medium=rss
tags:
  - cve-2022-40684
  - fortinet
  - authentication-bypass
  - network-appliance
  - initial-access
vendors:
  - Cloudflare
products:
  - BasedApparel.com
  - Chrome
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1133
    technique_name: External Remote Services
cve_verification:
  CVE-2022-40684:
    status: verified
    source: nvd
    checked_at: 2026-11-28T04:33:02.610715171Z
cves:
  - id: CVE-2022-40684
    cvss: 9.8
    epss: 0.98893
    kev: true
    kev_status: "true"
references:
  - https://www.wordfence.com/blog/2022/10/threat-advisory-cve-2022-40684-fortinet-appliance-auth-bypass/
  - https://www.horizon3.ai/fortios-fortiproxy-and-fortiswitchmanager-authentication-bypass-technical-deep-dive-cve-2022-40684/
  - https://github.com/horizon3ai/CVE-2022-40684
  - https://www.horizon3.ai/fortinet-iocs-cve-2022-40684/
  - https://attackerkb.com/topics/QWOxGIKkGx/cve-2022-40684/rapid7-analysis
  - https://github.com/rapid7/metasploit-framework/pull/17143
  - https://hackread.com/fbi-chief-kash-patel-store-hacked-infostealer-clickfix/
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KLJUNOWSKY-CVE-2022-40684-POC&utm_source=rss&utm_medium=rss
iocs:
  - type: domain
    value: BasedApparel.com
ioc_counts:
  domain: 1
rules:
  - title: Fortinet Appliance Auth Bypass Attempt
    description: Detects attempts to exploit CVE-2022-40684 by monitoring requests to the /api/v2/cmdb/system/admin endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1133
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Fortinet Appliance Admin Creation via API
    description: Detects attempts to create new administrator accounts via the Fortinet API, potentially indicating CVE-2022-40684 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1133
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-05-25T16:25:46Z"
    level: L2
    summary: added CVE-2022-40684
    sources:
      - hackread
  - at: "2026-11-20T03:10:25Z"
    level: L3
    summary: exploited:true; KEV CVE-2022-40684
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - at: "2026-11-28T04:33:03Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KLJUNOWSKY-CVE-2022-40684-POC&utm_source=rss&utm_medium=rss
---

## Overview

CVE-2022-40684 is an authentication bypass vulnerability affecting Fortinet appliances, specifically FortiOS, FortiProxy, and FortiSwitchManager. Successful exploitation allows a remote attacker to bypass authentication and perform unauthorized administrative actions via crafted HTTP requests. Public exploits and Metasploit modules targeting this vulnerability were quickly developed and released after the vulnerability was disclosed in late 2022. The vulnerability stems from an improper access control issue, allowing attackers to interact with the REST API without proper authentication. The primary targets are organizations using unpatched Fortinet appliances, and the impact can range from data theft and denial of service to complete network compromise.

## Attack Chain

1. The attacker identifies a vulnerable Fortinet appliance exposed to the internet.
2. The attacker crafts a malicious HTTP request to the `/api/v2/cmdb/system/admin` endpoint, bypassing authentication checks.
3. The attacker uses the `PUT` or `POST` HTTP methods to modify existing administrator accounts or create new accounts.
4. The attacker adds an SSH key to an administrator account to gain persistent remote access.
5. The attacker uses the newly created or modified administrator account to log into the Fortinet appliance's web interface or SSH.
6. The attacker reconfigures firewall rules to allow unauthorized network traffic.
7. The attacker exfiltrates sensitive data from the network through the compromised Fortinet appliance.
8. The attacker uses the compromised appliance as a pivot point to access other internal systems.

## Impact

Successful exploitation of CVE-2022-40684 can lead to complete compromise of the Fortinet appliance and the network it protects. Attackers can gain unauthorized access to sensitive data, disrupt network services, and use the compromised appliance as a foothold for further attacks within the network. This vulnerability has been widely exploited, impacting numerous organizations across various sectors. Unpatched systems are at high risk of being compromised.

## Recommendation

*   Apply the latest Fortinet patches to address CVE-2022-40684 on all FortiOS, FortiProxy, and FortiSwitchManager appliances immediately.
*   Deploy the Sigma rule `Fortinet Appliance Auth Bypass Attempt` to your SIEM to detect exploitation attempts targeting the `/api/v2/cmdb/system/admin` endpoint.
*   Enable web server logging on Fortinet appliances to ensure the Sigma rule can effectively detect malicious activity.
*   Review existing user accounts and SSH keys for any unauthorized additions or modifications.
*   Monitor network traffic for suspicious outbound connections originating from Fortinet appliances.
*   Implement network segmentation to limit the impact of a successful breach.
