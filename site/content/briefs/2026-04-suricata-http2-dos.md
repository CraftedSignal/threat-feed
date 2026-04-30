---
title: Suricata HTTP2 Continuation Frame Flooding Denial of Service (CVE-2026-31935)
slug: 2026-04-suricata-http2-dos
description: A denial of service vulnerability, CVE-2026-31935, exists in Suricata versions prior to 7.0.15 and 8.0.4, where flooding the system with crafted HTTP2 continuation frames leads to memory exhaustion and process termination.
date: "2026-04-02T15:16:37Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve
  - dos
  - http2
  - suricata
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-31935
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31935
  - https://github.com/OISF/suricata/security/advisories/GHSA-vxrp-5pg7-7v4x
  - https://redmine.openinfosecfoundation.org/issues/8289
rules:
  - title: Detect Suspicious HTTP2 Continuation Frame Flooding
    description: Detects potential denial-of-service attempts by monitoring for an excessive number of HTTP2 continuation frames within a short timeframe.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Suricata Process Memory Usage Spike
    description: Detects a sudden increase in memory usage by the Suricata process, potentially indicating a memory exhaustion attack.
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

CVE-2026-31935 describes a denial-of-service vulnerability affecting Suricata, a network IDS, IPS, and NSM engine. The vulnerability lies in the processing of HTTP2 continuation frames. Versions prior to 7.0.15 and 8.0.4 are susceptible to memory exhaustion when flooded with maliciously crafted HTTP2 continuation frames. This excessive memory consumption typically results in the operating system shutting down the Suricata process to prevent system instability. The vulnerability was reported and patched by the Open Information Security Foundation (OISF), the maintainers of Suricata, in versions 7.0.15 and 8.0.4. This vulnerability can be exploited by unauthenticated attackers from the network.

## Attack Chain

1. The attacker identifies a vulnerable Suricata instance running a version prior to 7.0.15 or 8.0.4.
2. The attacker establishes an HTTP2 connection with the target Suricata instance.
3. The attacker crafts a series of malicious HTTP2 continuation frames.
4. The attacker floods the Suricata instance with these crafted continuation frames over the established HTTP2 connection.
5. The Suricata process attempts to allocate memory to process the excessive number of continuation frames.
6. Memory consumption rapidly increases as the vulnerable code fails to properly handle the flood of continuation frames.
7. The system reaches its memory limit, leading to resource exhaustion.
8. The operating system intervenes and terminates the Suricata process to prevent further system instability, resulting in a denial-of-service.

## Impact

Successful exploitation of CVE-2026-31935 results in a denial-of-service condition, effectively disabling the Suricata instance's ability to perform network intrusion detection and prevention. This can leave networks unprotected from malicious traffic. The vulnerability can be triggered remotely without authentication, making it a readily exploitable threat. The precise number of affected Suricata deployments is unknown, but organizations relying on Suricata for network security monitoring are potentially at risk.

## Recommendation

*   Upgrade all Suricata installations to version 7.0.15 or 8.0.4 or later to patch CVE-2026-31935.
*   Deploy the Sigma rule "Detect Suspicious HTTP2 Continuation Frame Flooding" to monitor for potential exploitation attempts.
*   Monitor Suricata process health and resource consumption for unexpected spikes in memory usage that could indicate a denial-of-service attack.
