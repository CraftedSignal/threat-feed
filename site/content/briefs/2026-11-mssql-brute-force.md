---
brief_id: brief-2026-11-13-mssql-brute-force
event_id: brief-2026-11-13-mssql-brute-force
revision: 1
activity_at: "2026-11-13T10:13:30Z"
title: 'Microsoft SQL Server: Brute-force campaign and T-SQL malware deployment'
slug: 2026-11-mssql-brute-force
description: FortiGuard Labs reported a campaign that brute-forces Microsoft SQL Server logins and uses T-SQL to deploy Monero miners and Gh0st RAT.
date: "2026-11-13T10:13:30Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - mssql
  - brute-force
  - cryptominer
  - rat
vendors:
  - Microsoft
products:
  - SQL Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110.001
    technique_name: Password Guessing
    evidence: FortiGuard Labs analyzes a campaign that brute-forces Microsoft SQL Server logins
    confidence_band: high
references:
  - https://feeds.fortinet.com/_/28/972883538/fortinet/blog/threat-research
  - https://feeds.fortinet.com/~/972883538/0/fortinet/blog/threat-research~TSQL-Being-Abused-to-Deliver-Malware-on-Compromised-MS-SQL-Servers
action_plan:
  hunt_leads:
    - lead: Aggregate authentication logs by source IP address and identify high-frequency failed login attempts directed at MS SQL Server accounts over a short duration.
      technique_id: T1110.001
      data_needed:
        - SQL Server Error Logs
        - Windows Security Event Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: FortiGuard Labs analyzes a campaign that brute-forces Microsoft SQL Server logins
---

FortiGuard Labs identified a campaign where attackers brute-force Microsoft SQL Server logins and abuse T-SQL commands to deploy a Monero miner and Gh0st RAT.

## Attack Chain
1. Initial Access: Attackers perform brute-force attacks against Microsoft SQL Server logins.
2. Execution: Attackers use T-SQL commands to deploy malicious payloads, specifically a Monero miner and Gh0st RAT.
