---
title: Malicious NPM Packages Target Strapi Users
slug: 2026-04-strapi-npm-attack
description: A threat actor published 36 malicious NPM packages disguised as Strapi plugins in a supply chain attack, designed to execute code, escape containers, harvest credentials, and establish persistent implants on Linux systems targeting Strapi users, with specific focus on the Guardarian cryptocurrency payment gateway.
date: "2026-04-07T10:00:00Z"
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

A threat actor has compromised the Strapi ecosystem by publishing 36 malicious NPM packages posing as legitimate Strapi plugins. This supply chain attack, discovered by SafeDep, targets users of the open-source headless CMS, Strapi, which is built on Node.js. The malicious packages contain a variety of payloads designed to compromise Strapi installations. These payloads include capabilities for Redis code execution, Docker container escape, credential harvesting, reverse shell deployment, and…
