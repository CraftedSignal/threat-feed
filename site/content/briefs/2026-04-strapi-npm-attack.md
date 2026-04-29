---
title: Malicious NPM Packages Target Strapi Users
slug: 2026-04-strapi-npm-attack
description: A threat actor published 36 malicious NPM packages disguised as Strapi plugins in a supply chain attack, designed to execute code, escape containers, harvest credentials, and establish persistent implants on Linux systems targeting Strapi users, with specific focus on the Guardarian cryptocurrency payment gateway.
date: "2026-04-07T10:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - supply-chain
  - npm
  - strapi
  - malware
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: JavaScript'
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588.006
    technique_name: 'Obtain Capabilities: Install Software'
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
references:
  - https://www.securityweek.com/guardarian-users-targeted-with-malicious-strapi-npm-packages/
rules:
  - title: Detect Suspicious NPM Package Installation
    description: Detects the installation of NPM packages from the command line that match a list of suspicious names.
    platform: sigma
    severity: medium
    tactics:
      - supply_chain
    techniques:
      - T1199
    data_sources:
      - process_creation
      - linux
  - title: Detect Reverse Shell Activity from Strapi Server
    description: Detects reverse shell connections initiated from a Strapi server, potentially indicating a compromised system.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
  - title: Detect Strapi Configuration File Modification
    description: Detects modification of Strapi configuration files, which may indicate unauthorized access or tampering.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 3
---

A threat actor has compromised the Strapi ecosystem by publishing 36 malicious NPM packages posing as legitimate Strapi plugins. This supply chain attack, discovered by SafeDep, targets users of the open-source headless CMS, Strapi, which is built on Node.js. The malicious packages contain a variety of payloads designed to compromise Strapi installations. These payloads include capabilities for Redis code execution, Docker container escape, credential harvesting, reverse shell deployment, and establishing persistent implants. The attackers specifically targeted the cryptocurrency payment gateway Guardarian, indicating a focus on financial gain and data exfiltration from this specific organization. The malicious activity was observed starting around April 6, 2026.

## Attack Chain

1.  The attacker publishes 36 malicious NPM packages to the NPM registry, using names that mimic legitimate Strapi plugins to entice Strapi developers to install them.
2.  A Strapi developer installs one or more of the malicious NPM packages into their Strapi project using the `npm install` command.
3.  Upon installation, the malicious package executes its payload, which may include Redis code execution by injecting crontab entries and deploying PHP/Node.js reverse shells.
4.  The payload attempts to escape Docker containers via overlay filesystem discovery, writing shells to host directories and launching a reverse shell.
5.  The malicious code harvests credentials from the compromised system, including database passwords, API keys, JWT secrets, Elasticsearch credentials, and wallet/key files.
6.  The attacker gains a reverse shell on the compromised system, allowing them to execute arbitrary commands and further explore the network.
7.  The malware exfiltrates Strapi configurations and Guardarian API module data to an external attacker-controlled server.
8.  The attacker establishes persistent implants on the compromised system to maintain long-term access and control.

## Impact

This supply chain attack can lead to severe consequences for Strapi users, particularly those in the cryptocurrency sector. If successful, the attack allows for unauthorized access to sensitive data, including API keys, database credentials, and customer information. The direct targeting of Guardarian suggests a high-value target with potential for significant financial loss. A successful attack could result in data breaches, financial theft, and reputational damage for affected organizations. The ability to escape Docker containers further broadens the attack surface, potentially compromising the host system and other containers running on the same infrastructure.

## Recommendation

*   Deploy the "Detect Suspicious NPM Package Installation" Sigma rule to identify potentially malicious package installations (see rule below).
*   Enable process creation logging with command-line arguments to facilitate detection and investigation of suspicious activity.
*   Rotate all credentials, including database passwords, API keys, JWT secrets, and other secrets stored on systems where the malicious packages may have been installed, as recommended in the overview.
*   Monitor network connections for reverse shell activity originating from Strapi servers, as described in the Attack Chain (reference network_connection log source in Sigma rules).
*   Implement file integrity monitoring to detect unauthorized modifications to Strapi configuration files and other sensitive files (reference file_event log source in Sigma rules).
