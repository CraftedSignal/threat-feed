---
title: Budibase REST Connector SSRF via Empty Blacklist
slug: 2026-04-budibase-ssrf
description: A critical Server-Side Request Forgery (SSRF) vulnerability in Budibase's REST datasource connector allows attackers with Builder privileges to exfiltrate sensitive data from internal network services due to a missing default IP blacklist.
date: "2026-04-04T12:00:00Z"
severities:
  - critical
tags:
  - ssrf
  - budibase
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Remote Services Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.001
    technique_name: 'Remote Services: RDP'
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114.001
    technique_name: 'Email Collection: Local Email Collection'
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
references:
  - https://github.com/advisories/GHSA-7r9j-r86q-7g45
rules:
  - title: Detect Budibase REST Datasource Creation Targeting Internal IPs
    description: Detects the creation of Budibase REST datasources that target internal IP addresses, indicating potential SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Budibase Query Execution Targeting Internal REST Datasources
    description: Detects execution of queries that use a REST datasource pointing to a private IP address, indicating potential SSRF exploitation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical Server-Side Request Forgery (SSRF) vulnerability exists in Budibase version 3.30.6, affecting self-hosted instances that do not explicitly configure the `BLACKLIST_IPS` environment variable. The vulnerability resides within the REST datasource connector and the backend-core blacklist module. Due to the absence of a default IP blacklist, the `isBlacklisted()` function in `packages/backend-core/src/blacklist/blacklist.ts` unconditionally returns `false`, bypassing SSRF protection. This…
