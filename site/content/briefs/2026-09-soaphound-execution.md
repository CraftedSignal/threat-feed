---
title: Detection of SOAPHound Active Directory Collection Tool
slug: 2026-09-soaphound-execution
description: Detection of the .NET-based SOAPHound utility used for unauthorized extraction of Active Directory data via Active Directory Web Services.
date: "2026-09-03T12:39:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - discovery
  - active-directory
  - tool-usage
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: SOAPHound is a .NET tool for collecting Active Directory data.
    confidence_band: high
rules:
  - title: Detect HackTool - SOAPHound Execution
    description: Detects the execution of SOAPHound, a .NET tool for collecting Active Directory data, using specific command-line arguments that may indicate an attempt to extract sensitive AD information.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1087
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM environment.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for processes matching SOAPHound command-line patterns.
      technique_id: T1087
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
---

SOAPHound is a .NET-based offensive security tool designed to collect sensitive data from Active Directory (AD) environments. It interacts with Active Directory Web Services (ADWS) to perform enumeration and data exfiltration. The tool is commonly used during the reconnaissance and discovery phases of an attack to gather information such as domain structure, object properties, and certificate templates. Defenders should monitor for the execution of this tool, as its presence often signals an attempt to map the network or identify targets for privilege escalation. The tool supports various dumping operations, including certificate and DNS enumeration, which are indicative of an active adversary attempting to gain deeper visibility into the internal infrastructure.

## Impact

Successful use of SOAPHound allows unauthorized actors to perform comprehensive enumeration of Active Directory environments, facilitating lateral movement and target identification. This compromises the integrity and confidentiality of AD services, potentially leading to domain-wide security risks.

## Recommendation

- Deploy the provided Sigma rule to monitor for process creation events associated with SOAPHound command-line arguments.
- Implement monitoring for ADWS traffic or abnormal LDAP queries originating from non-administrative endpoints.
- Establish baseline monitoring for .NET assembly execution to identify the usage of unauthorized administrative tools.
