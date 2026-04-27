---
title: Impact of Poor Security Operation Center (SOC) Metrics
slug: 2024-01-02-soc-metrics
description: Poorly chosen performance metrics can significantly impair a SOC's ability to detect and respond to threats, leading to ineffective security operations and potential compromise.
date: "2024-01-02T10:00:00Z"
severities:
  - medium
tags:
  - soc
  - metrics
  - threat-hunting
  - detection
products:
  - SharePoint
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
references:
  - https://www.ncsc.gov.uk/blogs/could-your-choice-of-metrics-be-harming-your-soc
rules:
  - title: Detect Password Searches in SharePoint
    description: Detects attempts to locate passwords within SharePoint, which can be an indicator of reconnaissance or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
      - linux
  - title: Excessive HTTP 404 Errors from Single Source IP
    description: Detects potential scanning activity by identifying a high volume of 404 errors originating from a single IP address.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The National Cyber Security Centre (NCSC) blog post highlights the detrimental effects of using inappropriate metrics to evaluate SOC performance. Focusing on easily quantifiable metrics like 'number of tickets processed', 'time taken to close a ticket', 'number of detection rules written', and 'volume of logs collected' can incentivize analysts to prioritize metric optimization over effective threat detection. These perverse incentives can lead to a high number of false positives, alert…
