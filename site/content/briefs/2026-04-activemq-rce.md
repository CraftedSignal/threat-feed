---
title: Apache ActiveMQ Classic RCE via Jolokia API Exploitation
slug: 2026-04-activemq-rce
description: A remote code execution vulnerability (CVE-2026-34197) in Apache ActiveMQ Classic allows authenticated attackers to invoke management operations through the Jolokia API to retrieve a remote configuration file and execute OS commands, potentially exploitable without authentication via CVE-2024-32114.
date: "2026-04-08T14:30:27Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - activemq
  - rce
  - jolokia
  - cve-2026-34197
  - cve-2024-32114
  - cve-2022-41678
  - spring-xml
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
cves:
  - id: CVE-2026-34197
    cvss: 8.8
    epss: 0.65266
  - id: CVE-2024-32114
    cvss: 8.5
    epss: 0.02024
  - id: CVE-2022-41678
    cvss: 8.8
    epss: 0.93623
references:
  - https://www.securityweek.com/rce-bug-lurked-in-apache-activemq-classic-for-13-years/
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
