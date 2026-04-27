---
title: Schneider Electric Modicon PLC Denial-of-Service Vulnerability
slug: 2024-05-modicon-dos
description: Team82 disclosed vulnerabilities in Schneider Electric Modicon Controllers M241, M251, and M262 PLC lines, which can allow an attacker to cause a denial-of-service condition and affect controller availability.
date: "2026-03-23T19:15:23Z"
severities:
  - high
tags:
  - plc
  - denial-of-service
  - industrial-control-system
  - modicon
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://www.reddit.com/r/netsec/comments/1s1qhra/vulnerability_disclosure_schneider_electric/
  - http://claroty.com/team82/disclosure-dashboard
  - https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-069-01&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-069-01.pdf
ioc_counts:
  url: 2
rules:
  - title: Possible Modbus DoS Attempt
    description: Detects a large number of Modbus requests to a PLC, which could indicate a denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - zeek
  - title: Detect Multiple connections to Schneider Electric PLC on standard port
    description: Detects a high number of connections to port 502, the standard port for Modbus, which is used by Schneider Electric PLCs.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 23, 2026, Team82 disclosed vulnerabilities affecting Schneider Electric's Modicon M241, M251, and M262 programmable logic controllers (PLCs). These vulnerabilities, if exploited, can lead to a denial-of-service (DoS) condition, impacting the availability of the controller and potentially disrupting industrial processes. The Schneider Electric advisory SEVD-2026-069-01 addresses these issues, which were discovered by Claroty's Team82. Successful exploitation could halt critical…
