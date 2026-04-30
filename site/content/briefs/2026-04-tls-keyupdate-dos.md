---
title: CVE-2026-32283 Unauthenticated TLS 1.3 KeyUpdate DoS Vulnerability
slug: 2026-04-tls-keyupdate-dos
description: CVE-2026-32283 is a vulnerability in crypto/tls that allows unauthenticated TLS 1.3 KeyUpdate records, leading to persistent connection retention and a denial-of-service condition.
date: "2026-04-30T08:43:55Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - denial-of-service
  - tls
  - crypto/tls
vendors:
  - Microsoft
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-32283
    cvss: 7.5
    epss: 0.00017
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32283
rules:
  - title: Detect TLS 1.3 KeyUpdate Messages Without Authentication
    description: Detects suspicious TLS 1.3 KeyUpdate messages lacking proper authentication, potentially indicating an attempted denial-of-service attack.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
  - title: Detect High Volume of TLS KeyUpdate Records from Single Source IP
    description: Detects a high volume of TLS KeyUpdate records originating from a single source IP address within a short timeframe, potentially indicating a DoS attack.
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

CVE-2026-32283 describes a vulnerability within the crypto/tls component related to the processing of TLS 1.3 KeyUpdate records. The core issue stems from the lack of proper authentication for these KeyUpdate records. An attacker exploiting this flaw can send unauthenticated KeyUpdate records to a vulnerable server. The server, upon processing these records, may retain connections persistently or enter a denial-of-service (DoS) state due to resource exhaustion. This vulnerability poses a significant risk to systems relying on TLS 1.3 for secure communication. While the specific vulnerable products are not detailed in the source, the report does mention Microsoft as the affected vendor. Defenders must identify and patch the vulnerable crypto/tls implementations to mitigate this risk.

## Attack Chain

1.  Attacker establishes a TLS 1.3 connection with a vulnerable server.
2.  Attacker crafts a malicious TLS 1.3 KeyUpdate record without proper authentication.
3.  Attacker sends the unauthenticated KeyUpdate record to the target server over the established TLS connection.
4.  The vulnerable crypto/tls implementation on the server processes the malformed KeyUpdate record.
5.  Due to the lack of proper validation, the server's connection state becomes inconsistent.
6.  The server retains the connection persistently due to the invalid state.
7.  Attacker repeats steps 2-6 to exhaust server resources with numerous persistent connections.
8.  The server enters a denial-of-service (DoS) condition, becoming unresponsive to legitimate requests.

## Impact

Successful exploitation of CVE-2026-32283 can lead to a denial-of-service condition, rendering affected servers unavailable. The number of affected victims will vary based on the deployment of vulnerable crypto/tls implementations. Services relying on TLS 1.3 for secure communication are at risk. If the attack succeeds, legitimate users will be unable to access the affected services, potentially causing significant disruption and financial losses.

## Recommendation

*   Identify all systems using the crypto/tls component from Microsoft to determine if they are vulnerable to CVE-2026-32283.
*   Apply the security updates released by Microsoft to patch CVE-2026-32283 on all affected systems as soon as they are available, according to the Microsoft Security Update Guide.
*   Monitor network traffic for suspicious TLS KeyUpdate records, focusing on malformed or unauthenticated packets using a network intrusion detection system (NIDS).
