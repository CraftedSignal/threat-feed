---
brief_id: brief-2026-11-05-lxd-devlxd-hijack
event_id: brief-2026-11-05-lxd-devlxd-hijack
revision: 3
activity_at: "2026-11-11T21:55:33Z"
revision_history:
  - revision: 2
    at: "2026-11-08T21:57:23Z"
    checksum: sha256:1a2b9dcbfd14ebce7bb347a832ac84330f4d402725e4f2219517e52376429bbe
    summary: severity → critical; OS linux
    changed_fields:
      - action_plan
      - affected_os
      - affected_products
      - lastmod
      - references
      - severity
      - tags
      - ttps
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-9j25-mm2h-2f76
  - revision: 3
    at: "2026-11-11T21:55:33Z"
    checksum: sha256:c678231be51d149d7ff1116cead8efb928d2d7fe34d49d5cda4589e55c497515
    summary: new product
    changed_fields:
      - affected_products
      - exploitation_evidence
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-pjff-c2wc-f6jm
title: 'LXD: Cross-guest storage volume hijacking (CVE-2026-12411)'
slug: 2026-11-lxd-devlxd-hijack
description: An authorization flaw in the LXD DevLXD storage API allows an authenticated guest container to attach and gain read/write access to arbitrary storage volumes owned by other guests within the same project.
date: "2026-11-05T22:30:36Z"
lastmod: "2026-11-11T21:54:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:canonical:lxd:*:*:*:*:*:*:*:*
tags:
  - container-security
  - privilege-escalation
  - symlink-vulnerability
vendors:
  - Canonical
products:
  - LXD (>= 0.0.0-20250721152936-fe86ceb2c3fa, < 0.0.0-20260626085133-7cb96ac80a6d)
  - LXD (< 0.0.0-20260626085134-124f90100640)
  - LXD
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A guest can mount another guest's custom storage volume over /dev/lxd and read or write its contents without owning it.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Below, we place the exec_UUID.stdout file in /etc/cron.d on the host for arbitrary command execution.
    confidence_band: high
cves:
  - id: CVE-2026-12411
    cvss: 8.4
    epss: 0.00288
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-hhf9-qw4v-72xp
  - https://github.com/advisories/GHSA-9j25-mm2h-2f76
  - https://github.com/lxc/incus/security/advisories/GHSA-48q5-w887-33wv
  - https://github.com/lxc/incus/security/advisories/GHSA-f6m5-xw2g-xc4x
  - https://github.com/advisories/GHSA-pjff-c2wc-f6jm
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Patch LXD instances to version 0.0.0-20260626085133-7cb96ac80a6d or later.
      owner: IT Operations
      due: 48h
      evidence: Source notes fixed version for CVE-2026-12411.
    - action: Patch all instances of LXD to 0.0.0-20260626085134-124f90100640 or later.
      owner: IT Operations
      due: 24h
      evidence: Source advisory confirms patch availability.
  hunt_leads:
    - lead: Identify abnormal usage of the DevLXD PATCH API to add disk devices.
      technique_id: T1068
      data_needed:
        - LXD daemon logs (audit logs)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The attack involves frequent PATCH requests to add disk devices with custom volumes.
    - lead: Search for unexpected files created in critical directories (e.g., /etc/cron.d/, /etc/systemd/system/) owned by the LXD process or appearing with UUID-style filenames.
      technique_id: T1068
      data_needed:
        - File integrity monitoring (FIM) or auditd logs for directory write events.
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PoC demonstrates creation of /etc/cron.d/exec_* files.
  mitigation_plan:
    - priority: immediate
      action: Disable security.devlxd.management.volumes for all instances.
      owner: IT Operations
      addresses: CVE-2026-12411
      evidence: Source states this flag enables the vulnerable path.
    - priority: immediate
      action: Upgrade LXD to the fixed version.
      owner: IT Operations
      addresses: Arbitrary file write via symlink
      evidence: GHSA-9j25-mm2h-2f76
updates:
  - at: "2026-11-08T21:56:29Z"
    level: L3
    summary: severity → critical; OS linux
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-9j25-mm2h-2f76
  - at: "2026-11-11T21:54:32Z"
    level: L1
    summary: new product
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-pjff-c2wc-f6jm
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
