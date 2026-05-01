---
title: Prosody XML Parsing Denial-of-Service Vulnerability (CVE-2026-43507)
slug: 2026-05-prosody-dos
description: Prosody versions before 0.12.6 and versions 1.0.0 through 13.0.0 before 13.0.5 are susceptible to a denial-of-service attack via memory exhaustion caused by XML parsing resource amplification from unauthenticated connections (CVE-2026-43507).
date: "2026-05-01T15:16:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - xml-parsing
  - memory-exhaustion
vendors:
  - Prosody
products:
  - Prosody (< 0.12.6)
  - Prosody (1.0.0 - < 13.0.5)
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-43507
    cvss: 5.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43507
  - https://prosody.im/security/advisory_735dd9d3/
rules:
  - title: Detect Suspicious Prosody Memory Usage
    description: Detects suspicious memory usage by the Prosody process, potentially indicating a denial-of-service attack related to CVE-2026-43507.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Multiple Unauthenticated Connections to Prosody
    description: Detects a high number of unauthenticated connections to the Prosody server, potentially indicating an attempt to exploit CVE-2026-43507.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A denial-of-service vulnerability has been identified in Prosody, an XMPP server. The vulnerability, designated CVE-2026-43507, stems from the server's handling of XML parsing, where unauthenticated connections can trigger excessive memory consumption. This amplification effect can lead to memory exhaustion, rendering the service unavailable. The vulnerability affects Prosody versions before 0.12.6 and versions 1.0.0 through 13.0.0 before 13.0.5. This vulnerability allows unauthenticated attackers to cause significant disruption, impacting communication services.

## Attack Chain

1. An unauthenticated attacker establishes a connection to the Prosody server.
2. The attacker sends a specially crafted XML payload to the server.
3. The Prosody server begins parsing the malicious XML data.
4. Due to the crafted nature of the XML, the parsing process consumes excessive memory resources.
5. The server allocates more and more memory to handle the XML parsing request.
6. The memory consumption continues to increase, exhausting available system resources.
7. The server becomes unresponsive due to memory exhaustion, leading to a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-43507 results in a denial-of-service condition, rendering the Prosody server unavailable. This can disrupt messaging and communication services relying on the affected Prosody instance. The impact includes the inability to send or receive messages, potentially affecting organizations using Prosody for internal or external communication. The vulnerability allows unauthenticated attackers to trigger the denial of service, broadening the attack surface.

## Recommendation

*   Upgrade Prosody to version 0.12.6 or 13.0.5 or later to patch CVE-2026-43507, as per the vendor advisory.
*   Monitor Prosody server resource usage (CPU, memory) for unusual spikes, which may indicate an ongoing attack.
*   Implement rate limiting for incoming connections to mitigate potential amplification attacks.
*   Deploy the Sigma rule `DetectSuspiciousProsodyMemoryUsage` to detect unusual memory consumption patterns associated with this vulnerability.
