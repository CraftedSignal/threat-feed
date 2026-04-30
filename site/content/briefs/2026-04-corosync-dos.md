---
title: Corosync Integer Overflow Vulnerability (CVE-2026-35092) Leads to DoS
slug: 2026-04-corosync-dos
description: CVE-2026-35092 is an integer overflow vulnerability in Corosync's join message sanity validation, allowing a remote, unauthenticated attacker to send crafted UDP packets, resulting in a denial of service condition.
date: "2026-04-01T14:16:57Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-35092
  - denial-of-service
  - corosync
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-35092
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35092
  - https://access.redhat.com/security/cve/CVE-2026-35092
  - https://bugzilla.redhat.com/show_bug.cgi?id=2453169
  - https://bugzilla.redhat.com/show_bug.cgi?id=2453814
rules:
  - title: Detect Suspicious Corosync UDP Traffic
    description: Detects potentially malicious UDP traffic targeting Corosync instances that may indicate an exploitation attempt of CVE-2026-35092.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - linux
  - title: Detect Corosync Crash Events
    description: Detects when the Corosync service crashes, potentially due to exploitation of CVE-2026-35092
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-35092 describes an integer overflow vulnerability found in Corosync, a cluster engine. This vulnerability resides in the join message sanity validation process. A remote, unauthenticated attacker can exploit this flaw by sending specially crafted User Datagram Protocol (UDP) packets to a vulnerable Corosync instance. Successful exploitation leads to a service crash, effectively causing a denial of service (DoS). The vulnerability specifically targets Corosync deployments utilizing the totemudp or totemudpu modes. Defenders should be aware of unusual UDP traffic patterns directed towards Corosync instances, especially those configured with totemudp/totemudpu.

## Attack Chain

1.  Attacker identifies a Corosync instance running in totemudp/totemudpu mode.
2.  The attacker crafts a malicious UDP packet designed to trigger an integer overflow in the join message sanity validation.
3.  The attacker sends the crafted UDP packet to the targeted Corosync instance.
4.  The Corosync service receives the malicious UDP packet.
5.  The join message sanity validation process attempts to process the malformed packet, leading to an integer overflow.
6.  The integer overflow causes a crash within the Corosync service.
7.  The Corosync service terminates or becomes unresponsive.
8.  Legitimate cluster communications are disrupted, resulting in a denial of service.

## Impact

Successful exploitation of CVE-2026-35092 results in a denial-of-service condition, disrupting cluster communications and potentially impacting critical services relying on Corosync for high availability. The impact is significant for organizations using Corosync clusters to maintain service uptime, as a crash can lead to service outages. While the specific number of vulnerable deployments is unknown, organizations utilizing Corosync, especially in totemudp/totemudpu mode, are at risk.

## Recommendation

*   Monitor UDP traffic for unusual patterns indicative of exploitation attempts targeting Corosync instances.
*   Deploy the Sigma rule `Detect Suspicious Corosync UDP Traffic` to identify potentially malicious UDP packets sent to Corosync instances.
*   Investigate any detected instances of `CWE-190` (Integer Overflow or Wraparound) related to Corosync processes.
*   Refer to Red Hat's security advisory (https://access.redhat.com/security/cve/CVE-2026-35092) for potential patches or mitigations as they become available.
