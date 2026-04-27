---
title: CrowdStrike Flex for Services Expands Access to Incident Response
slug: 2026-03-falcon-flex-services
description: CrowdStrike's Falcon Flex for Services expands access to incident response and proactive security services, offering flexible consumption models to address evolving cybersecurity threats and improve incident readiness.
date: "2026-03-24T09:00:00Z"
severities:
  - medium
tags:
  - incident-response
  - security-services
  - falcon-flex
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-extends-the-falcon-flex-model-to-services/
rules:
  - title: Detect Potential Incident Response Engagement via Network Connection
    description: Detects potential engagement of an incident response provider by monitoring network connections to known IR provider domains.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - network_connection
      - windows
  - title: Detect Potential Incident Response Engagement via Process Creation
    description: Detects potential engagement of an incident response provider by monitoring process creation events for tools often used during incident response activities.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has extended its Falcon Flex model to its services offerings, providing organizations with more flexibility and speed in preparing for and responding to modern cybersecurity threats. This includes the introduction of the Zero Dollar Flex Fund, which offers proactive service hours designed to strengthen incident readiness. The Falcon Flex for Services allows customers to draw down from a standalone services entitlement across the CrowdStrike services portfolio, which includes…
