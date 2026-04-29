---
title: CrowdStrike Falcon Next-Gen SIEM Integrates with Microsoft Defender
slug: 2026-03-falcon-siem-defender
description: CrowdStrike's Falcon Next-Gen SIEM is expanding to support third-party EDR solutions, starting with Microsoft Defender, to unify detection, investigation, and response without requiring a Falcon sensor.
date: "2026-03-30T06:30:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - siem
  - edr
  - microsoft defender
  - crowdstrike falcon
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Data Stream Contains Falcon Onum
    description: Detects when a data stream contains Falcon Onum indicating data transformation
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - network_connection
      - windows
  - title: ExtraHop Network Connection
    description: Detects network connections to ExtraHop indicating possible data integration
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CrowdStrike is enhancing its Falcon Next-Gen SIEM platform to incorporate telemetry from third-party endpoint detection and response (EDR) solutions, beginning with Microsoft Defender. Announced on March 23, 2026, this integration allows organizations to modernize their security operations center (SOC) by unifying detection, investigation, and response workflows without mandating the replacement of existing endpoint agents. This aims to address the increasing complexity of modern attacks that span across different domains, including endpoint, identity, network, and cloud environments. The integration includes Falcon Onum, which filters, enriches, and routes data in motion to reduce noise before it reaches downstream systems, improving data fidelity and lowering infrastructure costs. This reduces the data tax and helps accelerate security outcomes.

## Attack Chain

This brief describes how CrowdStrike is making its SIEM interoperate with 3rd party EDR solutions. This is not a description of attacker behavior.

## Impact

The successful integration of Microsoft Defender data into CrowdStrike Falcon Next-Gen SIEM allows security teams to centralize their security operations. It enables faster detection of cross-domain attacks, more efficient investigations, and quicker response times. By removing the need to replace existing endpoint agents, organizations can avoid the costs and complexities associated with rip-and-replace strategies. This helps streamline SOC operations and improve overall security posture by providing a more comprehensive view of the threat landscape. The integration with Falcon Onum also reduces storage costs and improves data fidelity.

## Recommendation

*   Evaluate the benefits of integrating Microsoft Defender telemetry into Falcon Next-Gen SIEM to consolidate security operations.
*   Implement Falcon Onum within the Falcon platform to filter, enrich, and route data in motion, reducing noise and storage costs as mentioned in the overview.
*   Utilize the federated search capabilities of Falcon Next-Gen SIEM to investigate across live, network, and archived data sources, as described in the overview.
