---
brief_id: brief-2024-01-03-juniper-rce
event_id: brief-2024-01-03-juniper-rce
revision: 2
activity_at: "2026-11-20T03:11:01Z"
revision_history:
  - revision: 2
    at: "2026-11-20T03:11:01Z"
    checksum: sha256:1f6b27b6f8a0ecc2517af7bc4694ddf4719adf115db45dcccfc0e35274bb84b8
    summary: exploited:true; KEV CVE-2023-36846; KEV CVE-2023-36847; KEV CVE-2023-36844; KEV CVE-2023-36845
    changed_fields:
      - cpes
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Juniper Networks J-Web Remote Code Execution Vulnerability Exploitation
slug: 2024-01-juniper-rce
description: Exploitation attempts targeting Juniper Networks J-Web interface via the webauth_operation.php endpoint to achieve remote code execution.
date: "2024-01-03T15:00:00Z"
lastmod: "2026-11-20T03:10:25Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2023-11-13T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:-:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r1-s1:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r1:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r2-s1:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r2-s2:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r2:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r3-s1:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r3-s2:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r3-s3:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r3-s4:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r3-s5:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r3-s6:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r3-s7:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r3-s8:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:20.4:r3:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:21.1:r1-s1:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:21.1:r1:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:21.1:r2-s1:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:21.1:r2-s2:*:*:*:*:*:*
  - cpe:2.3:o:juniper:junos:21.1:r2:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XNEHRU-CVE-2023-36845-JUNIPER-VULNERABILITY&utm_source=rss&utm_medium=rss
tags:
  - juniper
  - rce
  - cve-2023-36844
  - cve-2023-36845
  - cve-2023-36846
  - cve-2023-36847
vendors:
  - Juniper
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
cves:
  - id: CVE-2023-36844
    cvss: 5.3
    epss: 0.91357
    kev: true
    kev_status: "true"
  - id: CVE-2023-36845
    cvss: 9.8
    epss: 0.94265
    kev: true
    kev_status: "true"
  - id: CVE-2023-36846
    cvss: 5.3
    epss: 0.95101
    kev: true
    kev_status: "true"
  - id: CVE-2023-36847
    cvss: 5.3
    epss: 0.85769
    kev: true
    kev_status: "true"
references:
  - https://supportportal.juniper.net/s/article/2023-08-Out-of-Cycle-Security-Bulletin-Junos-OS-SRX-Series-and-EX-Series-Multiple-vulnerabilities-in-J-Web-can-be-combined-to-allow-a-preAuth-Remote-Code-Execution?language=en_US
  - https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-36844.yaml
  - https://thehackernews.com/2023/08/new-juniper-junos-os-flaws-expose.html
  - https://github.com/watchtowrlabs/juniper-rce_cve-2023-36844
  - https://labs.watchtowr.com/cve-2023-36844-and-friends-rce-in-juniper-firewalls/
  - https://vulncheck.com/blog/juniper-cve-2023-36845
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XNEHRU-CVE-2023-36845-JUNIPER-VULNERABILITY&utm_source=rss&utm_medium=rss
rules:
  - title: Juniper J-Web RCE via webauth_operation.php
    description: Detects attempts to exploit the Juniper J-Web RCE vulnerability by monitoring requests to the webauth_operation.php endpoint with a PHPRC parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Juniper J-Web RCE Reverse Shell
    description: Detects potential reverse shell connections initiated from a Juniper J-Web server after successful RCE exploitation.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1105
    data_sources:
      - network_connection
      - firewall
  - title: Juniper J-Web Suspicious PHP Upload
    description: Detects a suspicious attempt to upload PHP files to Juniper J-Web server.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 3
updates:
  - at: "2026-08-28T19:17:56Z"
    level: L2
    summary: poc_available; added CVE-2023-36844 +3
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XNEHRU-CVE-2023-36845-JUNIPER-VULNERABILITY&utm_source=rss&utm_medium=rss
  - at: "2026-11-20T03:10:25Z"
    level: L3
    summary: exploited:true; KEV CVE-2023-36846; KEV CVE-2023-36847; KEV CVE-2023-36844; KEV CVE-2023-36845
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Juniper Networks devices, specifically those using the J-Web interface, are susceptible to remote code execution vulnerabilities. These vulnerabilities, including CVE-2023-36844, CVE-2023-36845, CVE-2023-36846, and CVE-2023-36847, allow attackers to execute arbitrary code on affected systems. The primary attack vector involves sending malicious requests to the `/webauth_operation.php` endpoint with manipulated `PHPRC` parameters. Successful exploitation grants the attacker unauthorized access, potentially leading to data theft, network compromise, and complete system control. Exploitation attempts have been observed targeting vulnerable Juniper SRX and EX series devices. Publicly available exploit code exists, increasing the likelihood of widespread exploitation.

## Attack Chain

1.  The attacker identifies a vulnerable Juniper Networks device running J-Web.
2.  The attacker crafts a malicious HTTP POST request targeting the `/webauth_operation.php` endpoint.
3.  The request includes a `PHPRC` parameter containing PHP code designed to execute commands on the server.
4.  The vulnerable J-Web interface processes the request without proper sanitization.
5.  The attacker's PHP code executes with the privileges of the web server process.
6.  The attacker establishes a reverse shell connection to an external server using `nc` or `bash -i`.
7.  The attacker uses the reverse shell to execute commands, enumerate the system, and escalate privileges.
8.  The attacker installs a persistent backdoor, exfiltrates sensitive data, and pivots to other internal systems.

## Impact

Successful exploitation of these vulnerabilities allows attackers to gain complete control over Juniper Networks devices. This can lead to data theft, network outages, and further compromise of internal networks. The vulnerabilities affect a wide range of Juniper SRX and EX series devices, potentially impacting numerous organizations. If successful, attackers can deploy ransomware, steal intellectual property, or disrupt critical network services.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM to detect exploitation attempts (rules: "Juniper J-Web RCE via webauth_operation.php" and "Juniper J-Web RCE Reverse Shell").
*   Inspect web server logs for requests to `/webauth_operation.php?PHPRC=*` (IOC: `url: /webauth_operation.php?PHPRC=*`) and investigate any matches.
*   Monitor for outbound network connections from Juniper devices to unusual or suspicious IP addresses, which may indicate a reverse shell (rule: "Juniper J-Web RCE Reverse Shell").
*   Patch CVE-2023-36844, CVE-2023-36845, CVE-2023-36846, and CVE-2023-36847 on all affected Juniper devices immediately.
