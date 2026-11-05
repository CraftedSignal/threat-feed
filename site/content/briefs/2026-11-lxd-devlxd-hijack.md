---
brief_id: brief-2026-11-05-lxd-devlxd-hijack
event_id: brief-2026-11-05-lxd-devlxd-hijack
revision: 1
activity_at: "2026-11-05T22:30:36Z"
title: 'LXD: Cross-guest storage volume hijacking (CVE-2026-12411)'
slug: 2026-11-lxd-devlxd-hijack
description: An authorization flaw in the LXD DevLXD storage API allows an authenticated guest container to attach and gain read/write access to arbitrary storage volumes owned by other guests within the same project.
date: "2026-11-05T22:30:36Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:canonical:lxd:*:*:*:*:*:*:*:*
vendors:
  - Canonical
products:
  - LXD (>= 0.0.0-20250721152936-fe86ceb2c3fa, < 0.0.0-20260626085133-7cb96ac80a6d)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A guest can mount another guest's custom storage volume over /dev/lxd and read or write its contents without owning it.
    confidence_band: high
cves:
  - id: CVE-2026-12411
    cvss: 8.4
    epss: 0.00288
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-hhf9-qw4v-72xp
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch LXD instances to version 0.0.0-20260626085133-7cb96ac80a6d or later.
      owner: IT Operations
      due: 48h
      evidence: Source notes fixed version for CVE-2026-12411.
  hunt_leads:
    - lead: Identify abnormal usage of the DevLXD PATCH API to add disk devices.
      technique_id: T1068
      data_needed:
        - LXD daemon logs (audit logs)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The attack involves frequent PATCH requests to add disk devices with custom volumes.
  mitigation_plan:
    - priority: immediate
      action: Disable security.devlxd.management.volumes for all instances.
      owner: IT Operations
      addresses: CVE-2026-12411
      evidence: Source states this flag enables the vulnerable path.
---

LXD is susceptible to cross-guest volume hijacking due to missing ownership checks in the instance device-update path. When `security.devlxd.management.volumes` is enabled, the API fails to validate if an identity has ownership of a custom storage volume during a `PATCH` request to update instance devices. This enables a malicious guest to attach volumes belonging to other guests, resulting in full read/write access to the victim’s data. Volume names can be discovered via error probing.

## Attack Chain
1. Attacker obtains a valid DevLXD identity with `can_edit` permissions for their own instance.
2. Attacker probes for volume names by attempting to attach them via `PATCH` requests to the DevLXD instance endpoint.
3. LXD processes the `PATCH` request for a disk device.
4. The `devLXDInstancePatchHandler` validates the device configuration shape (type, pool, source) but skips volume ownership/RBAC checks.
5. LXD attaches the victim's volume to the attacker's instance.
6. Attacker reads or overwrites data within the mounted volume at the specified mount point.

## Impact
Exploitation allows for unauthorized access, modification, and potential data exfiltration of storage volumes belonging to other tenants within the same LXD project. The impact is limited to environments where `security.devlxd.management.volumes` is explicitly enabled.

## Recommendation
- Upgrade LXD to the version containing the fix for CVE-2026-12411 (>= 0.0.0-20260626085133-7cb96ac80a6d).
- In environments where patching is deferred, disable `security.devlxd.management.volumes` for all instances in shared projects.
- Audit existing LXD instance configurations to identify unauthorized or unexpected disk devices.
