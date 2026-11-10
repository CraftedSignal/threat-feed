---
brief_id: brief-2026-11-10-gstreamer-uaf
event_id: brief-2026-11-10-gstreamer-uaf
revision: 1
activity_at: "2026-11-10T13:47:02Z"
title: 'GStreamer: Use-after-free in buffer value deserialization (CVE-2026-125704)'
slug: 2026-11-gstreamer-uaf
description: A use-after-free vulnerability in GStreamer core buffer value deserialization allows for remote unauthenticated denial-of-service against applications processing untrusted caps or structure data.
date: "2026-11-10T13:47:02Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
products:
  - GStreamer (< unknown fixed version)
cves:
  - id: CVE-2026-125704
    cvss: 7.5
    kev_status: "false"
references:
  - https://gstreamer.freedesktop.org/security/sa-2026-0028.html
  - https://access.redhat.com/security/cve/CVE-2026-125704
  - https://bugzilla.redhat.com/show_bug.cgi?id=2569128
  - https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/11583.patch
  - https://sploitus.com/exploit?id=CVE-2026-125704&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all applications utilizing GStreamer, focusing on network-facing GDP receivers.
      owner: IT Operations
      due: 24h
      evidence: A network-facing GStreamer Data Protocol receiver is susceptible to remote unauthenticated crashes.
  hunt_leads:
    - lead: Identify and investigate services that exhibit frequent crashes or unexpected restarts related to GStreamer library loading.
      data_needed:
        - System crash logs (e.g., /var/log/syslog, journald)
        - Application-specific logs showing deserialization errors or memory faults
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An application that parses untrusted caps or structure data could crash.
  mitigation_plan:
    - priority: immediate
      action: Apply the vendor-provided patch for CVE-2026-125704 to all identified GStreamer instances.
      owner: IT Operations
      addresses: CVE-2026-125704
      evidence: https://gstreamer.freedesktop.org/security/sa-2026-0028.html
---

A use-after-free vulnerability exists in GStreamer core during the deserialization of buffer values. When the library processes serialized buffer data containing invalid characters, an error path triggers a premature free of a mapped buffer before it is unmapped. This flaw can be triggered remotely without user interaction, specifically when targeting a network-facing GStreamer Data Protocol (GDP) receiver. While the primary documented impact is an application crash, the memory corruption nature of the vulnerability may allow for further exploitation paths that remain currently undisclosed.

## Impact
Successful exploitation results in an application crash (denial of service). The vulnerability is reachable over the network without authentication or user interaction when the target application processes untrusted caps or structure data.

## Recommendation
- Update all GStreamer installations to the version containing the fix documented in the GStreamer security advisory (SA-2026-0028).
- Review network-facing services using the GStreamer Data Protocol (GDP) and restrict access to trusted sources until patching is completed.
- Monitor logs for repeated application crashes or service restarts in processes utilizing GStreamer libraries, which may indicate exploitation attempts.
