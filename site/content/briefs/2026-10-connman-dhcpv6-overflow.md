---
brief_id: brief-2026-10-23-connman-dhcpv6-overflow
event_id: brief-2026-10-23-connman-dhcpv6-overflow
revision: 1
activity_at: "2026-10-23T19:51:12Z"
title: 'ConnMan: Stack-based buffer overflow in DHCPv6 (CVE-2026-115863)'
slug: 2026-10-connman-dhcpv6-overflow
description: ConnMan versions up to and including 2.0 contain a stack-based buffer overflow in the DHCPv6 client, allowing an on-link attacker to cause a root-privileged service crash.
date: "2026-10-23T19:51:12Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Verified against NVD metadata
cpes:
  - cpe:2.3:a:connman:connman:*:*:*:*:*:*:*:*
vendors:
  - ConnMan
products:
  - ConnMan (<= 2.0)
cves:
  - id: CVE-2026-115863
    cvss: 7.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115863
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  hunt_leads:
    - lead: Monitor for unexpected termination or restarts of the connmand service
      data_needed:
        - Systemd journal or syslog logs showing service crash, segmentation faults, or service restart events for connmand
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The impact is unauthenticated on-link crash of connmand (runs as root).
  mitigation_plan:
    - priority: immediate
      action: Identify and inventory all systems running ConnMan <= 2.0
      owner: IT Operations
      addresses: CVE-2026-115863
      evidence: ConnMan through 2.0 has a stack-based buffer overflow
---

ConnMan versions up to and including 2.0 are vulnerable to a stack-based buffer overflow in the DHCPv6 implementation. The vulnerability resides in the `get_domains` function within `gdhcp/client.c`. Improper handling of the DOMAIN_LIST (option 24) in DHCPv6 Reply messages allows for memory corruption during DNS label parsing. The flaw is triggered when the client processes a crafted Reply message containing a DOMAIN_LIST option exceeding 1025 bytes, resulting in out-of-bounds reads and writes.

## Impact

Successful exploitation allows an unauthenticated, on-link attacker to crash the `connmand` service. Because `connmand` typically operates with root privileges, this results in a denial-of-service condition for the affected system's network management functionality.

## Recommendation

Identify systems running `connmand` versions 2.0 or earlier. Monitor vendor security channels for the release of a patched version of ConnMan and schedule upgrades accordingly. As this is an on-link network attack, segment vulnerable systems where possible until patches are applied.
