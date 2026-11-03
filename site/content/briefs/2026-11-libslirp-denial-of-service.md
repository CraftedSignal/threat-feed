---
brief_id: brief-2026-11-03-libslirp-denial-of-service
event_id: brief-2026-11-03-libslirp-denial-of-service
revision: 1
activity_at: "2026-11-03T04:05:06Z"
title: 'libslirp: Denial of service in if_output (CVE-2026-120831)'
slug: 2026-11-libslirp-denial-of-service
description: A queue pointer corruption vulnerability in libslirp allows an adjacent attacker to crash the host networking process via burst traffic, leading to a denial of service.
date: "2026-11-03T04:05:06Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Vulnerability acknowledged by upstream
cpes:
  - cpe:2.3:a:freedesktop:libslirp:*:*:*:*:*:*:*:*
vendors:
  - FreeDesktop
products:
  - libslirp
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A guest generating burst traffic could crash the host networking process, causing a denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-120831
    cvss: 6.5
    kev_status: "false"
references:
  - https://access.redhat.com/security/cve/CVE-2026-120831
  - https://bugzilla.redhat.com/show_bug.cgi?id=2565425
  - https://gitlab.freedesktop.org/slirp/libslirp/-/commit/bad35bd3b529dc47aa109980a69a36da7848ab76
  - https://sploitus.com/exploit?id=CVE-2026-120831&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
  hunt_leads:
    - lead: Monitor for unexpected termination or restart of virtualization networking processes (e.g., qemu, libvirtd) coinciding with high network traffic spikes
      technique_id: T1498
      data_needed:
        - Host system logs (dmesg, syslog, journalctl)
        - Virtualization management service logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: A guest generating burst traffic could crash the host networking process
  mitigation_plan:
    - priority: immediate
      action: Identify and patch libslirp components in virtualized environments
      owner: IT Operations
      addresses: CVE-2026-120831
      evidence: Source documentation on Red Hat Bugzilla
---

A vulnerability exists in the libslirp library within the `if_output()` function, identified as CVE-2026-120831. An attacker can trigger memory corruption when the library attempts to move a session from the fast queue to the batch queue. By unlinking and reinserting an arbitrary packet via `ifm->m_nextpkt` instead of the session queue head, the library corrupts internal queue pointers.

## Impact
Successful exploitation results in a crash of the host networking process, leading to a denial of service for the affected host. This impact is confirmed by the Red Hat bugzilla report.

## Recommendation
- Inventory systems utilizing libslirp, particularly virtual machine hosts or container runtimes relying on this user-mode networking library.
- Review the provided Red Hat Bugzilla report and Gitlab commit for patch availability or mitigating configuration changes.
- Prioritize patching for internet-facing or multi-tenant virtualization environments where an adjacent attacker could potentially reach the interface.
