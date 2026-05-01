---
title: Prosody Memory Exhaustion Vulnerability (CVE-2026-43506)
slug: 2026-05-prosody-dos
description: Prosody versions before 0.12.6, versions 1.0.0 through 13.0.0, and before version 13.0.5 are vulnerable to a denial of service due to memory leaks from unauthenticated connections, leading to memory exhaustion.
date: "2026-05-01T15:16:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - memory exhaustion
  - prosody
vendors:
  - Prosody
products:
  - Prosody
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
cves:
  - id: CVE-2026-43506
    cvss: 5.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43506
  - https://prosody.im/security/advisory_735dd9d3/
  - https://www.openwall.com/lists/oss-security/2026/05/01/5
rules:
  - title: Detect High Number of Unauthenticated Connections to Prosody
    description: This rule detects a high number of unauthenticated connections to a Prosody server, which could indicate a denial-of-service attack exploiting CVE-2026-43506.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
  - title: Prosody Server Memory Usage Spike
    description: Detects a significant increase in memory usage by the Prosody process, which could indicate a memory leak vulnerability being exploited.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A denial of service vulnerability, identified as CVE-2026-43506, affects Prosody, a popular XMPP server. The vulnerability exists in versions prior to 0.12.6, versions 1.0.0 through 13.0.0, and before version 13.0.5. Successful exploitation of this vulnerability results in a denial-of-service condition due to memory exhaustion. The root cause is memory leaks triggered by unauthenticated connections, which gradually consume server resources until the system becomes unresponsive. This vulnerability was publicly disclosed on May 1, 2026, and poses a risk to organizations using affected versions of Prosody, as it can disrupt communication services and impact overall system availability.

## Attack Chain

1.  An attacker establishes an unauthenticated connection to the Prosody server.
2.  The connection triggers a memory leak within the Prosody server software.
3.  The memory leak consumes a small amount of system memory.
4.  The attacker repeatedly establishes new unauthenticated connections.
5.  Each connection triggers further memory leaks, compounding the memory consumption.
6.  The server's available memory is gradually exhausted due to the accumulated leaks.
7.  As memory resources diminish, the Prosody server's performance degrades.
8.  Eventually, the Prosody server becomes unresponsive, resulting in a denial-of-service condition.

## Impact

The successful exploitation of CVE-2026-43506 can lead to a denial-of-service condition, rendering the Prosody XMPP server unavailable. This can disrupt communication services for organizations relying on the affected Prosody versions. The impact can range from temporary service interruptions to prolonged outages, depending on the severity of the memory exhaustion and the organization's recovery capabilities. There is no specific information available on the number of victims or specific sectors targeted.

## Recommendation

-   Upgrade Prosody servers to version 0.12.6 or 13.0.5 or later to remediate CVE-2026-43506.
-   Monitor Prosody server resource utilization, specifically memory consumption, for unusual increases that could indicate exploitation attempts.
-   Deploy the Sigma rules provided in this brief to detect potential denial-of-service attacks exploiting CVE-2026-43506 by monitoring connection patterns.
