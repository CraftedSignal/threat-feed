---
title: CrowdStrike Falcon Flex for Services Expansion
slug: 2026-03-crowdstrike-falcon-flex
description: CrowdStrike is expanding the Falcon Flex model to its services offering to provide organizations with more flexible access to incident response and proactive security services.
date: "2026-03-24T12:00:00Z"
severities:
  - medium
tags:
  - incident response
  - security services
  - MDR
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-extends-the-falcon-flex-model-to-services/
rules:
  - title: Detect Potential Initial Access via Unsolicited Network Connection
    description: Detects a process initiating an outbound network connection that is not typically associated with network activity. This could indicate unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - windows
  - title: Detect Execution of Suspicious Process in Temp Directory
    description: Detects execution of a process in a temp directory. This is often indicative of malware or malicious activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike is extending the Falcon Flex model, previously focused on platform consumption, to its expert-led cybersecurity services. Announced in March 2026, this expansion provides organizations with a more adaptable way to consume services like incident response, proactive security assessments, advisory, platform services, and training. The new "Zero Dollar Flex Fund" offers qualifying new customers 200 hours of CrowdStrike Services at no initiation cost, including 160 hours of incident…
