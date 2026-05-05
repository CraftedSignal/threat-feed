---
title: ABB B&R Automation Runtime Denial-of-Service Vulnerability
slug: 2026-05-abb-automation-dos
description: A denial-of-service vulnerability (CVE-2025-11044) exists in ABB B&R Automation Runtime versions prior to 6.5 and R4.93, where an unauthenticated attacker can exploit a race condition to cause permanent denial-of-service.
date: "2026-05-05T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - ics
  - cve-2025-11044
vendors:
  - ABB
products:
  - ABB B&R Automation Runtime
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2025-11044
    cvss: 6.8
    epss: 0.0006
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-125-03
  - https://www.cve.org/CVERecord?id=CVE-2025-11044
  - https://cwe.mitre.org/data/definitions/770.html
rules:
  - title: Detect Potential ABB B&R Automation Runtime DoS Attempt
    description: Detects network connections to the ANSL server on port 8888, indicative of potential exploitation of CVE-2025-11044.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499
    data_sources:
      - network_connection
      - windows
  - title: Detect Excessive Connections to ANSL Server
    description: Detects a high number of connections to port 8888 from a single source IP address within a short timeframe, which may indicate a DoS attempt against the ANSL server.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

ABB B&R Automation Runtime is affected by a denial-of-service vulnerability.  Specifically, versions prior to 6.5 and prior to R4.93 are susceptible. The vulnerability, tracked as CVE-2025-11044, resides in the ANSL-Server component. An unauthenticated attacker with network access can exploit a race condition, leading to a permanent denial-of-service condition on affected devices. The vulnerability stems from an insufficient throttling and limiting mechanism in the ANSL Server. Exploitation requires access to the system network, either directly or through a misconfigured firewall. ABB recommends updating to Automation Runtime versions 6.5 or later and R4.93 or later to remediate this vulnerability. The initial report date for this vulnerability was 2026-01-19, with a CISA republication on 2026-05-05.

## Attack Chain

1. The attacker gains network access to the target ABB B&R Automation Runtime device, either through direct connection, compromised firewall, or malicious software on the network.
2. The attacker crafts a specially crafted message designed to exploit the race condition in the ANSL-Server.
3. The attacker sends the malicious message to the vulnerable ANSL-Server component of the Automation Runtime.
4. The ANSL-Server processes the message, triggering the vulnerability due to insufficient resource throttling.
5. The race condition occurs, leading to excessive resource allocation.
6. The affected device's resources are exhausted due to the unbounded resource allocation.
7. The Automation Runtime component becomes unresponsive, resulting in a denial-of-service condition.
8. The affected industrial control system node stops functioning, impacting critical manufacturing processes.

## Impact

Successful exploitation of CVE-2025-11044 can cause a permanent denial-of-service condition on the affected ABB B&R Automation Runtime devices. This can lead to the shutdown of critical manufacturing processes, resulting in production downtime, financial losses, and potential safety hazards. The vulnerability affects critical infrastructure sectors, particularly critical manufacturing, worldwide. While the advisory does not report specific victim counts, the widespread deployment of ABB B&R Automation Runtime suggests a broad potential impact.

## Recommendation

*   Immediately patch ABB B&R Automation Runtime to versions 6.5 or later, or R4.93 or later, to remediate CVE-2025-11044 as recommended by the vendor.
*   For systems that cannot be immediately patched, implement the mitigation measures suggested by ABB, such as adjusting application configurations to longer cycle times.
*   Limit the maximum data traffic and the maximum number of concurrent connections to the ANSL server of Automation Runtime on the Control Network Firewall as recommended by the vendor.
*   Deploy the following Sigma rule to detect suspicious network activity targeting the ANSL server, and tune for your specific environment.
*   Minimize network exposure for all control system devices and systems, ensuring they are not accessible from the internet, as per CISA's recommendations.
