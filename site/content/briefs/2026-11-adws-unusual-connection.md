---
brief_id: brief-2026-11-05-adws-unusual-connection
event_id: brief-2026-11-05-adws-unusual-connection
revision: 1
activity_at: "2026-11-05T12:58:03Z"
title: 'Active Directory Web Services: Unusual Network Connection Detection'
slug: 2026-11-adws-unusual-connection
description: This brief provides a detection mechanism to identify unauthorized or anomalous processes attempting to connect to Active Directory Web Services (ADWS) on port 9389, a technique potentially used for reconnaissance or data collection.
date: "2026-11-05T12:58:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Standard Sigma rule coverage.
tags:
  - windows
  - network-security
  - discovery
  - active-directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: The detection identifies processes interacting with ADWS, which is commonly abused to collect directory information.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_adws_unusual_connection.yml
  - https://medium.com/falconforce/soaphound-tool-to-collect-active-directory-data-via-adws-165aca78288c
rules:
  - title: Detect Uncommon Connection to Active Directory Web Services
    description: Detects uncommon network connections to the Active Directory Web Services (ADWS) from processes not typically associated with ADWS management.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087
    data_sources:
      - network_connection
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Identify all processes connecting to port 9389 in the environment to establish a baseline of authorized software.
      technique_id: T1087
      data_needed:
        - Network connection logs (EDR or Netflow)
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Establishing a baseline for ADWS interaction is necessary to minimize false positives for this detection.
---

Active Directory Web Services (ADWS) provides a web service interface to Active Directory instances. Adversaries can abuse this interface to query directory information without directly interacting with the LDAP service, often to evade traditional LDAP monitoring. This detection targets processes that initiate network connections to the ADWS default port (9389) that are not recognized as standard management utilities or known PowerShell binaries.

## Recommendation

* Deploy the provided Sigma rule to your SIEM to baseline and monitor outbound connections to port 9389 from domain-joined workstations and servers.
* Establish an allow-list of legitimate administrative tools or custom applications within your environment that are verified to interact with ADWS.
* Audit active connections to port 9389 to identify non-standard binaries performing directory discovery.
