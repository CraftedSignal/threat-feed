---
title: Cisco Crosswork Network Controller and Network Services Orchestrator Connection Exhaustion Denial of Service
slug: 2026-05-cisco-nso-dos
description: An unauthenticated remote attacker can cause a denial-of-service condition on Cisco Crosswork Network Controller and Network Services Orchestrator by exhausting connection resources via a high volume of connection requests.
date: "2026-05-07T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - cisco
  - network
vendors:
  - Cisco
products:
  - Crosswork Network Controller
  - Network Services Orchestrator
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nso-dos-7Egqyc
rules:
  - title: Cisco NSO/CNC Excessive Connections
    description: Detects a high number of connections to Cisco NSO or CNC from a single IP address, indicating a potential DoS attack.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
  - title: Cisco NSO/CNC Single Source Connections
    description: Detects initial connections to Cisco NSO or CNC from a single IP address, providing early warning.
    platform: sigma
    severity: informational
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Cisco Crosswork Network Controller (CNC) and Cisco Network Services Orchestrator (NSO) are susceptible to a denial-of-service (DoS) vulnerability due to inadequate rate-limiting on incoming network connections. Exploitation involves an unauthenticated, remote attacker sending a large number of connection requests to an affected system. This can exhaust available connection resources, rendering Cisco CNC and Cisco NSO unresponsive, leading to a DoS condition for legitimate users and dependent services. Recovery requires a manual reboot of the affected system. Cisco has released software updates to address this vulnerability, and no workarounds are available. This vulnerability is identified as CVE-2026-20188.

## Attack Chain

1.  The attacker identifies a vulnerable Cisco Crosswork Network Controller or Network Services Orchestrator instance exposed to the network.
2.  The attacker establishes multiple TCP connections to the targeted system.
3.  The attacker sends a high volume of connection requests to the targeted system over the established connections.
4.  The targeted system inadequately rate-limits the incoming connection requests.
5.  The flood of connection requests exhausts the available connection resources on the system.
6.  Cisco CNC and Cisco NSO become unresponsive due to resource exhaustion.
7.  Legitimate users and dependent services experience a denial-of-service condition.
8.  The system requires a manual reboot to restore normal operation.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition, rendering Cisco Crosswork Network Controller and Cisco Network Services Orchestrator unresponsive. Legitimate users are unable to access the services, and dependent services are disrupted. Recovery requires a manual reboot of the affected system, leading to downtime and potential data loss. The scope of impact depends on the criticality of CNC and NSO within the affected network infrastructure.

## Recommendation

*   Apply the latest software updates provided by Cisco to patch CVE-2026-20188 on all affected Cisco Crosswork Network Controller and Cisco Network Services Orchestrator instances.
*   Monitor network connections to Cisco Crosswork Network Controller and Cisco Network Services Orchestrator using the "Cisco NSO/CNC Excessive Connections" Sigma rule to detect potential DoS attacks.
*   Implement rate-limiting mechanisms on network devices and firewalls to restrict the number of connections from a single source IP address to Cisco Crosswork Network Controller and Cisco Network Services Orchestrator.
*   Investigate and block any suspicious IP addresses identified by the "Cisco NSO/CNC Single Source Connections" Sigma rule exhibiting unusually high connection attempts.
