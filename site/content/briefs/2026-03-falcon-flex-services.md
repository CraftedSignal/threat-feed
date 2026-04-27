---
title: CrowdStrike Falcon Flex for Services Expansion
slug: 2026-03-falcon-flex-services
description: CrowdStrike is expanding its Falcon Flex model to include its services, offering flexible consumption of expert-led cybersecurity services including incident response and proactive security measures.
date: "2026-03-28T08:13:20Z"
severities:
  - low
tags:
  - incident-response
  - security-services
  - crowdstrike
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0009
    tactic_name: Incident Response
    technique_id: T1578
    technique_name: Account Access
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-extends-the-falcon-flex-model-to-services/
rules:
  - title: CrowdStrike Services Engagement - Process Creation
    description: Detects process creation events that may be related to CrowdStrike services engagements based on specific process names often used during incident response or other service activities.
    platform: sigma
    severity: informational
    data_sources:
      - process_creation
      - windows
  - title: CrowdStrike Services Engagement - Network Connection
    description: Detects network connections that may be related to CrowdStrike services engagements based on connections to known CrowdStrike infrastructure or commonly used tools.
    platform: sigma
    severity: informational
    data_sources:
      - network_connection
      - windows
  - title: CrowdStrike Services Engagement - File Download
    description: Detects file downloads that may be related to CrowdStrike services engagements, focusing on commonly used tools for incident response and analysis.
    platform: sigma
    severity: informational
    data_sources:
      - file_event
      - windows
rules_count: 3
---

CrowdStrike has extended its Falcon Flex model to its services offering, allowing organizations to consume cybersecurity services with greater flexibility. This model enables organizations to draw down from a standalone services entitlement, applying it across CrowdStrike's services portfolio based on their specific priorities and operational needs. The Falcon Flex for Services covers incident response, proactive security services, advisory, platform services, and training. Additionally…
