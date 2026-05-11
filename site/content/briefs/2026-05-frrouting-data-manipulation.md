---
title: FRRouting Project FRRouting Vulnerability Allows Data Manipulation
slug: 2026-05-frrouting-data-manipulation
description: A remote, authenticated attacker can exploit a vulnerability in FRRouting Project FRRouting to manipulate data.
date: "2026-05-11T09:43:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - FRRouting Project
products:
  - FRRouting
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0914
rules:
  - title: Detect FRRouting Configuration Changes via CLI
    description: Detects FRRouting configuration changes via command-line interface
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - linux
  - title: Detect FRRouting Configuration File Modification
    description: Detects modification of FRRouting configuration files
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists in FRRouting Project FRRouting that allows a remote, authenticated attacker to manipulate data. The advisory provides limited details, but successful exploitation could lead to unauthorized modification of routing configurations, potentially disrupting network traffic or redirecting it to malicious destinations. Defenders should investigate logs for unusual routing protocol activity originating from authenticated users or sources and deploy detection rules to identify suspicious commands or configuration changes.

## Attack Chain

Due to limited information, the following attack chain is based on potential exploitation scenarios:

1. Attacker obtains valid credentials for FRRouting management interface.
2. Attacker logs into FRRouting management interface remotely.
3. Attacker issues commands to modify routing policies.
4. FRRouting software applies modified routing policies.
5. Network traffic is potentially redirected or disrupted based on modified policies.
6. Attacker monitors network traffic to confirm successful redirection or disruption.

## Impact

Successful exploitation of this vulnerability could lead to unauthorized data manipulation, resulting in network disruptions, traffic redirection, or other malicious activities. The lack of specific details prevents quantifying the number of potential victims or identifying targeted sectors. However, any organization relying on FRRouting for network management is potentially at risk.

## Recommendation

*   Monitor FRRouting logs for suspicious commands originating from authenticated users.
*   Implement the Sigma rules below to detect potentially malicious routing configuration changes.
