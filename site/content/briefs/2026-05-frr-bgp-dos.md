---
title: 'CVE-2026-37459: FRRouting BGP UPDATE Message Integer Underflow DoS'
slug: 2026-05-frr-bgp-dos
description: An integer underflow vulnerability, CVE-2026-37459, in FRRouting (FRR) versions stable/10.0 to stable/10.6 allows a remote attacker to cause a Denial of Service (DoS) by sending a crafted BGP UPDATE message.
date: "2026-05-19T07:13:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - bgp
  - dos
  - frrouting
  - network
vendors:
  - FRRouting
products:
  - FRR
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-37459
    cvss: 7.5
    epss: 0.00052
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-37459
  - CVE-2026-37459
rules:
  - title: Detect Suspicious BGP UPDATE Messages
    description: Detects CVE-2026-37459 exploitation — Monitors for BGP UPDATE messages from unusual sources
    platform: sigma
    severity: low
    tactics:
      - resource_development
    techniques:
      - T1588.002
    data_sources:
      - network_connection
      - linux
  - title: Detect FRR Process Crash
    description: Detects FRR process crashes by monitoring system logs for FRR termination events
    platform: sigma
    severity: informational
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - system
      - linux
rules_count: 2
---

CVE-2026-37459 is an integer underflow vulnerability affecting FRRouting (FRR), a widely used IP routing protocol suite for Linux and Unix platforms. The vulnerability resides in the BGP (Border Gateway Protocol) UPDATE message processing logic within FRR versions stable/10.0 to stable/10.6. A remote attacker can exploit this flaw by sending a specially crafted BGP UPDATE message to a vulnerable FRR instance, triggering an integer underflow. This underflow condition can lead to memory corruption or other unexpected behavior, ultimately causing the FRR process to crash and resulting in a Denial of Service (DoS) condition. This vulnerability poses a risk to network availability, as it can disrupt routing operations and impact network connectivity.

## Attack Chain

1.  Attacker identifies a vulnerable FRR instance running a version between stable/10.0 and stable/10.6.
2.  Attacker crafts a malicious BGP UPDATE message designed to trigger the integer underflow. The specific details of the message structure are not available in the provided source.
3.  Attacker sends the crafted BGP UPDATE message to the vulnerable FRR instance over TCP port 179, the standard BGP port.
4.  The FRR instance receives the BGP UPDATE message and begins processing it.
5.  During the processing of the BGP UPDATE message, the integer underflow occurs due to a calculation error.
6.  The integer underflow leads to memory corruption within the FRR process.
7.  The memory corruption causes the FRR process to crash.
8.  The crash of the FRR process results in a Denial of Service (DoS), disrupting routing operations.

## Impact

Successful exploitation of CVE-2026-37459 can lead to a Denial of Service (DoS) condition, impacting the availability of network routing services. While the exact number of affected organizations is unknown, FRR is used in a variety of network environments, including enterprise networks, service provider networks, and research networks. A successful attack could disrupt routing operations, leading to network outages, service disruptions, and potential financial losses.

## Recommendation

*   Upgrade FRRouting (FRR) to a patched version beyond stable/10.6 to remediate CVE-2026-37459.
*   Monitor network traffic for suspicious BGP UPDATE messages that may indicate exploitation attempts using the "Detect Suspicious BGP UPDATE Messages" Sigma rule.
*   Implement rate limiting for BGP UPDATE messages to mitigate the impact of a DoS attack.
