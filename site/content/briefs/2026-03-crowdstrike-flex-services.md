---
title: CrowdStrike Flex for Services Expands Access to Incident Response Expertise
slug: 2026-03-crowdstrike-flex-services
description: CrowdStrike is expanding its Falcon Flex model to its services offering, providing flexible access to incident response, proactive security services, advisory, platform services, and training.
date: "2026-03-28T08:17:27Z"
severities:
  - medium
tags:
  - incident-response
  - security-services
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-extends-the-falcon-flex-model-to-services/
rules:
  - title: Detect PowerShell Downgrade Attack
    description: Detects PowerShell being invoked with a version parameter to downgrade it.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detect Execution from Suspicious Folder
    description: Detects execution of a binary from folders commonly used to store downloads or temporary files.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike is extending the Falcon Flex model to its services offering to provide organizations with the flexibility and speed required to prepare for modern threats. This model provides flexible consumption of expert-led cybersecurity services. The Zero Dollar Flex Fund provides proactive services hours to strengthen incident readiness. Customers draw down from a standalone services entitlement that can be applied across the services portfolio based on priorities and operational needs. This…
