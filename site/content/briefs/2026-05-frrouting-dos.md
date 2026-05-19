---
title: FRRouting CVE-2026-37458 Denial of Service Vulnerability
slug: 2026-05-frrouting-dos
description: A denial-of-service vulnerability, identified as CVE-2026-37458, exists in the MP_REACH_NLRI component of FRRouting versions stable/10.0 to stable/10.6, where authenticated attackers can trigger a DoS by sending a crafted UPDATE message due to missing input validation.
date: "2026-05-19T07:13:08Z"
type: threat
types:
  - threat
severities:
  - medium
cpes:
  - cpe:2.3:a:frrouting:frrouting:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - network
  - frrouting
  - cve-2026-37458
vendors:
  - FRRouting
products:
  - FRR stable/10.0
  - FRR stable/10.1
  - FRR stable/10.2
  - FRR stable/10.3
  - FRR stable/10.4
  - FRR stable/10.5
  - FRR stable/10.6
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-37458
    cvss: 6.5
    epss: 0.00049
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-37458
rules:
  - title: Detect CVE-2026-37458 Exploitation Attempt - Malformed BGP UPDATE Message
    description: Detects CVE-2026-37458 exploitation attempts by identifying malformed BGP UPDATE messages with unusually large NLRI lengths, potentially indicating a DoS attack.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499
      - T1499.001
    data_sources:
      - network_connection
      - frr
rules_count: 1
---

FRRouting (FRR) is susceptible to a denial-of-service (DoS) vulnerability, tracked as CVE-2026-37458, affecting versions stable/10.0 through stable/10.6. The vulnerability lies within the MP_REACH_NLRI component and stems from a lack of input validation when processing UPDATE messages. An authenticated attacker can exploit this flaw by sending a specially crafted UPDATE message, leading to resource exhaustion or service interruption on the affected FRR instance. Successful exploitation can disrupt network routing and availability. Defenders should apply the appropriate patches or mitigations to prevent potential exploitation.

## Attack Chain

1. An authenticated attacker gains network access to an FRR instance running a vulnerable version (stable/10.0 to stable/10.6).
2. The attacker crafts a malicious BGP UPDATE message specifically targeting the MP_REACH_NLRI component.
3. This crafted UPDATE message contains invalid or oversized data within the NLRI (Network Layer Reachability Information) fields.
4. The attacker sends the crafted UPDATE message to the targeted FRR instance.
5. The FRR instance receives the crafted UPDATE message and attempts to process the malformed NLRI data.
6. Due to the missing input validation, the FRR instance consumes excessive resources (CPU, memory) while processing the invalid NLRI.
7. The resource exhaustion leads to a denial of service, impacting the routing functionality of the FRR instance.

## Impact

Successful exploitation of CVE-2026-37458 results in a denial-of-service condition, preventing the FRRouting instance from properly functioning. This can disrupt network routing, leading to connectivity issues and potential network outages. The impact is primarily a loss of availability for network services relying on the affected FRR instance. The number of potential victims depends on the deployment size of FRRouting within an organization's network infrastructure.

## Recommendation

*   Upgrade FRRouting instances to a patched version beyond stable/10.6 to remediate CVE-2026-37458.
*   Deploy the Sigma rule "Detect CVE-2026-37458 Exploitation Attempt - Malformed BGP UPDATE Message" to identify suspicious BGP UPDATE messages indicative of exploitation attempts.
*   Implement rate limiting for BGP UPDATE messages to mitigate the impact of potential DoS attacks.
*   Monitor network traffic for unusual patterns related to BGP UPDATE messages.
