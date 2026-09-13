---
title: Buffer Overflow Vulnerability in SIPp get_peer_tag()
slug: 2026-09-sipp-buffer-overflow
description: SIPp versions 3.7.7 and earlier contain a buffer overflow vulnerability in the get_peer_tag() function that allows remote attackers to cause a denial of service.
date: "2026-09-13T13:25:48Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:sipp:sipp:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
  - network-protocol
vendors:
  - SIPp
products:
  - SIPp (<= 3.7.7)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Unauthenticated remote attackers can send crafted SIP messages with oversized tag parameters to overflow the static buffer and crash the process.
    confidence_band: high
cves:
  - id: CVE-2026-90778
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90778
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Inventory SIPp deployments and restrict access to management interfaces
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-90778 impacts SIPp <= 3.7.7
  mitigation_plan:
    - priority: immediate
      action: Monitor for patched version of SIPp and upgrade once available
      owner: IT Operations
      addresses: CVE-2026-90778
      evidence: NVD vulnerability disclosure
---

SIPp versions 3.7.7 and earlier are vulnerable to a stack-based buffer overflow within the get_peer_tag() function. The vulnerability occurs during the processing of incoming SIP messages when a 'To' header contains a tag parameter exceeding 2048 bytes. An unauthenticated remote attacker can exploit this flaw by sending a specifically crafted SIP message to a listening SIPp instance. Successful exploitation results in the corruption of the stack memory, causing the SIPp process to crash, thereby leading to a denial-of-service condition. Because SIPp is frequently used in telecommunications infrastructure for load testing and stress testing, such a crash can cause significant service disruption in testing environments.

## Impact

The primary impact of this vulnerability is a denial-of-service condition where the SIPp service becomes unavailable due to process termination. This vulnerability affects users of SIPp 3.7.7 and earlier across all platforms. Organizations relying on SIPp for network performance validation or protocol testing are at risk of unexpected service outages if exposed to malicious SIP traffic.

## Recommendation

Update all instances of SIPp to a version later than 3.7.7. As the maintainers have not yet provided a fixed release in the source, monitor the official SIPp repository for patch releases addressing CVE-2026-90778. In the interim, implement ingress filtering or deep packet inspection on SIP traffic to identify and drop packets containing 'To' header tag parameters with lengths exceeding 2048 bytes.
