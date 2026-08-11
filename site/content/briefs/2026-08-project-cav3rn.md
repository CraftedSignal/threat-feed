---
title: Project CAV3RN Modular Espionage Framework
slug: 2026-08-project-cav3rn
description: Project CAV3RN is a modular espionage framework targeting entities in Israel that uses a .NET NativeAOT-compiled communication module to orchestrate DNS-controlled C2 transport switching between direct HTTPS and Google Apps Script relays.
date: "2026-08-11T10:29:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - espionage
  - c2
  - dns
  - nativeaot
  - modular
products:
  - .NET 8
  - Google Apps Script
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: The framework uses direct HTTPS C2 and Google Apps Script relays for communication.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.004
    technique_name: DNS
    evidence: The communication module performs DNS A-record queries to select between transport layers.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: The local broker discovers and loads DLL components to execute framework tasks.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The s_version handler enumerates DLLs under AppContext.BaseDirectory.
    confidence_band: high
references:
  - https://securelist.com/project-cav3rn-continues/120991/
iocs:
  - type: domain
    value: studiotikva.com
  - type: url
    value: https://api.studiotikva.com/api/v1/update/check
  - type: ip
    value: 12.19.29.30
ioc_counts:
  domain: 1
  ip: 1
  url: 1
rules:
  - title: Detect CAV3RN DNS C2 Infrastructure Queries
    description: Detects DNS queries to subdomains associated with the CAV3RN framework's control plane
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.004
    data_sources:
      - dns_query
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block studiotikva.com at the enterprise DNS perimeter.
      owner: SOC
      due: 24h
      evidence: Identified as the primary C2 domain in the Securelist report.
  hunt_leads:
    - lead: Search for DNS queries containing the pattern *.m.studiotikva.com or *.p.studiotikva.com
      technique_id: T1071.004
      data_needed:
        - DNS query logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: These patterns are hardcoded in the communication module's DNS polling mechanism.
  mitigation_plan:
    - priority: immediate
      action: Review process creation logs for execution from non-standard directories like AppContext.BaseDirectory
      owner: IT Operations
      addresses: Framework modular DLL execution
      evidence: Framework components are loaded dynamically by the local broker.
---

Project CAV3RN is a modular espionage framework discovered targeting organizations in Israel. Recent analysis has uncovered advanced orchestration capabilities within the framework's communication module, 'GoogleService.dll', which is compiled with .NET 8 NativeAOT. This framework employs a sophisticated C2 strategy where the malware queries an adversary-controlled domain to receive DNS A-record responses. These responses dictate the communication channel, allowing the attacker to toggle between direct HTTPS connectivity and a Google Apps Script relay. The infrastructure also allows the threat actor to remotely validate and rotate Google Apps Script deployment IDs, ensuring resilient communication and evasion of static infrastructure blocks. The framework relies on a local broker that manages DLL loading, system inventory collection, and runtime upgrades, facilitating long-term persistence and modular capability expansion.

## Attack Chain

1. The local broker initializes and registers the communication module 'GoogleService.dll'.
2. The module performs an internal handshake with the broker to verify identity using a fixed GUID.
3. The malware performs a DNS A-record query to 'studiotikva.com' to receive instructions on the preferred communication channel.
4. Depending on the DNS response (specifically the fourth octet), the module selects either a direct HTTPS endpoint or a Google Apps Script relay.
5. The module performs a deployment ID freshness check using further DNS queries to ensure the current Google Apps Script relay is valid.
6. The communication module executes internal commands such as 's_version' to inventory local DLLs or 's_write' to drop payloads to disk.
7. Data is serialized, XORed with 0xAC, Base64-encoded, and exfiltrated over the selected transport layer.

## Impact

Project CAV3RN is used in targeted espionage operations against entities in Israel. The framework's modular nature allows for customized payload delivery, system discovery, and persistent access, potentially leading to significant intellectual property theft and unauthorized information access within compromised environments.

## Recommendation

* Deploy network-level blocking for the C2 domain 'studiotikva.com' and monitor for suspicious DNS queries targeting this domain.
* Implement strict Egress filtering for traffic directed towards 'script.google.com' if not required for business operations, and monitor for unusual 'Google Apps Script' deployment usage.
* Enable process creation logging (Event ID 1) to detect suspicious DLL loading or execution patterns by unknown binaries in user-writable directories (e.g., AppContext.BaseDirectory).
* Monitor for anomalous DNS A-record traffic where the queried domain ends in '.m.studiotikva.com' or '.p.studiotikva.com'.
