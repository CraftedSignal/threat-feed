---
title: Ella Core Vulnerable to UE Downlink Redirection via Forged PDUSessionResourceSetupResponse (CVE-2026-44473)
slug: 2026-05-ella-core-downlink-redirection
description: Ella Core is vulnerable to UE downlink redirection (CVE-2026-44473) due to missing SCTP association verification, enabling a malicious radio to forge a PDUSessionResourceSetupResponse and redirect downlink traffic.
date: "2026-05-11T15:19:38Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - vulnerability
  - 5G
  - downlink redirection
  - CVE-2026-44473
vendors:
  - ellanetworks
products:
  - core (< 1.10.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1657
    technique_name: Service Impairment
references:
  - https://github.com/advisories/GHSA-qfxw-v8qx-vj3v
  - CVE-2026-44473
rules:
  - title: Detect Forged PDUSessionResourceSetupResponse from Unassociated SCTP
    description: Detects a forged PDUSessionResourceSetupResponse message originating from an unexpected SCTP association, indicating a potential downlink redirection attack related to CVE-2026-44473.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1657
    data_sources:
      - network_connection
      - linux
  - title: Detect NGAP Traffic from Unknown Radio
    description: Detects NGAP traffic originating from a radio that has not been properly registered within the network. This can be an early indicator of unauthorized radio access or a compromised radio attempting to inject malicious messages related to CVE-2026-44473.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Ella Core, a component in 5G networks, is vulnerable to a downlink redirection attack. A radio with a valid NG Setup can exploit this vulnerability by sending a forged PDUSessionResourceSetupResponse containing the AMF-UE-NGAP-ID of a target UE. The vulnerability, identified as CVE-2026-44473, lies in the core's failure to verify that the forged message arrived on the SCTP association bound to the UE's logical NG-connection. This allows a malicious radio to create a GTP tunnel to itself, redirecting downlink traffic intended for the targeted UE. This vulnerability affects versions prior to 1.10.0. Defenders need to implement proper checks and validations on the SCTP association to prevent unauthorized traffic redirection.

## Attack Chain

1. An attacker gains access to a radio with valid NG Setup credentials.
2. The attacker identifies the AMF-UE-NGAP-ID of a target UE.
3. The attacker crafts a forged PDUSessionResourceSetupResponse message, using the targeted UE's AMF-UE-NGAP-ID.
4. The attacker sends the forged PDUSessionResourceSetupResponse message to the Ella Core.
5. Due to the missing verification of the SCTP association, Ella Core processes the forged message.
6. Ella Core establishes a GTP tunnel towards the attacker's radio based on the forged message.
7. Downlink user-plane traffic intended for the targeted UE is routed to the attacker's radio.
8. The attacker can now intercept and potentially manipulate the redirected downlink traffic.

## Impact

Successful exploitation allows an attacker to redirect downlink user-plane traffic for a targeted UE to a rogue radio. This can lead to eavesdropping on user communications, data theft, or other malicious activities. The number of affected users depends on the scale of the attacker's operation. Sectors utilizing 5G networks are at risk. If successful, attackers can gain unauthorized access to sensitive data transmitted over the network.

## Recommendation

*   Upgrade Ella Core to version 1.10.0 or later to patch CVE-2026-44473, as described in the overview.
*   Implement network monitoring to detect suspicious PDUSessionResourceSetupResponse messages originating from unexpected SCTP associations, as this behavior would be detected by the Sigma rule "Detect Forged PDUSessionResourceSetupResponse from Unassociated SCTP".
*   Enforce strict validation of SCTP associations for all UE context lookups to prevent the processing of forged messages as detailed in the fix description.
