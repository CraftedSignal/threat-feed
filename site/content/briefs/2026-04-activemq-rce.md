---
brief_id: brief-2026-04-08-activemq-rce
event_id: brief-2026-04-08-activemq-rce
revision: 2
activity_at: "2026-11-13T23:25:53Z"
revision_history:
  - revision: 2
    at: "2026-11-13T23:25:53Z"
    checksum: sha256:4b38288fb43991885400187eaa3ece9d0ac806d408e5ff97a21072e34668fdd2
    summary: exploited:true; poc_available; KEV CVE-2026-34197
    changed_fields:
      - claim_state
      - cves
      - exploitation_evidence
      - has_poc
      - lastmod
      - poc_references
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ASDASDDQWDQ29-A11Y-CVE-2026-34197&utm_source=rss&utm_medium=rss
title: Apache ActiveMQ Classic RCE via Jolokia API Exploitation
slug: 2026-04-activemq-rce
description: A remote code execution vulnerability (CVE-2026-34197) in Apache ActiveMQ Classic allows authenticated attackers to invoke management operations through the Jolokia API to retrieve a remote configuration file and execute OS commands, potentially exploitable without authentication via CVE-2024-32114.
date: "2026-04-08T14:30:27Z"
lastmod: "2026-11-13T23:23:30Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-04-08T14:30:27Z"
  confidence: high
cpes:
  - cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:activemq_broker:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ASDASDDQWDQ29-A11Y-CVE-2026-34197&utm_source=rss&utm_medium=rss
tags:
  - activemq
  - rce
  - jolokia
  - cve-2026-34197
  - cve-2024-32114
  - cve-2022-41678
  - spring-xml
vendors:
  - Hitachi Energy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
cves:
  - id: CVE-2026-34197
    cvss: 8.8
    epss: 0.15492
    kev: true
    kev_status: "true"
  - id: CVE-2022-41678
    cvss: 8.8
    epss: 0.8581
    kev_status: "false"
  - id: CVE-2024-32114
    cvss: 8.5
    epss: 0.07148
    kev_status: "false"
references:
  - https://www.securityweek.com/rce-bug-lurked-in-apache-activemq-classic-for-13-years/
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-04
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ASDASDDQWDQ29-A11Y-CVE-2026-34197&utm_source=rss&utm_medium=rss
rules:
  - title: ActiveMQ Jolokia API Access
    description: Detects access to the Jolokia API endpoint in Apache ActiveMQ.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: ActiveMQ Suspicious Process Creation
    description: Detects suspicious process creation events originating from the ActiveMQ Java process.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
updates:
  - at: "2026-10-06T17:12:10Z"
    level: L1
    summary: new vendor
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-04
  - at: "2026-11-13T23:23:30Z"
    level: L3
    summary: exploited:true; poc_available; KEV CVE-2026-34197
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ASDASDDQWDQ29-A11Y-CVE-2026-34197&utm_source=rss&utm_medium=rss
---

A remote code execution vulnerability, CVE-2026-34197, has been identified in Apache ActiveMQ Classic, an open-source messaging and Integration Patterns server widely used across industries. This vulnerability, present for 13 years, allows attackers to invoke management operations through the Jolokia API and instruct the broker to retrieve a remote configuration file, leading to OS command execution. This is achieved by bypassing CVE-2022-41678, a previous bug that allowed webshell creation. Additionally, CVE-2024-32114 exposes the Jolokia API to unauthenticated users in ActiveMQ versions 6.0.0 through 6.1.1, enabling potential RCE without authentication. The vulnerability affects ActiveMQ Classic deployments and was addressed in versions 5.19.4 and 6.2.3.

## Attack Chain

1. Attacker identifies an Apache ActiveMQ Classic instance running a vulnerable version (prior to 5.19.4 or 6.2.3).
2. If the instance is running ActiveMQ 6.0.0 through 6.1.1, the attacker leverages CVE-2024-32114 to access the Jolokia API without authentication. Otherwise, the attacker authenticates to the ActiveMQ instance.
3. The attacker invokes management operations through the Jolokia API to target ActiveMQ's VM transport feature.
4. The attacker crafts a VM transport URI referencing a non-existent broker.
5. ActiveMQ creates the broker and accepts a parameter instructing it to load a configuration from a URL controlled by the attacker.
6. The attacker hosts a malicious Spring XML configuration file on a remote server.
7. The ActiveMQ broker retrieves and processes the malicious Spring XML configuration file.
8. The Spring XML file instantiates bean definitions that execute arbitrary OS commands, achieving remote code execution.

## Impact

Successful exploitation of these vulnerabilities could lead to complete compromise of the ActiveMQ server, potentially impacting numerous industries relying on this messaging middleware. Attackers could gain unauthorized access to sensitive data, disrupt message queues, and pivot to other systems within the network. The scope of the impact depends on the ActiveMQ deployment and the attacker's objectives. Unauthenticated exploitation via CVE-2024-32114 significantly broadens the attack surface.

## Recommendation

*   Upgrade Apache ActiveMQ Classic to versions 5.19.4 or 6.2.3 or later to address CVE-2026-34197.
*   For ActiveMQ versions 6.0.0 through 6.1.1, verify the configuration and security constraints to ensure the Jolokia API is not exposed without authentication, mitigating CVE-2024-32114.
*   Deploy the Sigma rule "ActiveMQ Jolokia API Access" to monitor for unauthorized access attempts to the Jolokia API.
*   Implement network segmentation to limit the blast radius in case of a successful compromise.
*   Monitor process creation events for suspicious processes spawned by the ActiveMQ Java process, leveraging the "ActiveMQ Suspicious Process Creation" Sigma rule.
