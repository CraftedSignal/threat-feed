---
brief_id: brief-2026-11-09-zt-zip-path-traversal
event_id: brief-2026-11-09-zt-zip-path-traversal
revision: 1
activity_at: "2026-11-09T22:14:58Z"
title: 'ZeroTurnaround zt-zip: Path traversal vulnerability (CVE-2026-63436)'
slug: 2026-11-zt-zip-path-traversal
description: The zt-zip library fails to validate destination boundaries within its fluent Zips API, allowing arbitrary file writes via path traversal sequences in ZIP entry names.
date: "2026-11-09T22:14:58Z"
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
  - cpe:2.3:a:zeroturnaround:zt-zip:*:*:*:*:*:*:*:*
vendors:
  - ZeroTurnaround
products:
  - zt-zip (< 1.18.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Applications that unpack attacker-controlled ZIP files through the Zips fluent API may allow arbitrary file writes outside the intended extraction directory
    confidence_band: high
cves:
  - id: CVE-2026-63436
    cvss: 6.1
    epss: 0.00242
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-52c6-99qm-3hqr
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63436
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade zt-zip to 1.18.0 or later
      owner: IT Operations
      due: 48h
      evidence: 'Affected Packages: maven/org.zeroturnaround:zt-zip (vulnerable: < 1.18.0)'
  hunt_leads:
    - lead: Identify applications utilizing the zt-zip library for processing user-supplied ZIP files
      technique_id: T1190
      data_needed:
        - Application dependency inventory (e.g., pom.xml/build.gradle)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Applications that unpack attacker-controlled ZIP files through the Zips fluent API may allow arbitrary file writes
  mitigation_plan:
    - priority: immediate
      action: Upgrade zt-zip dependency to 1.18.0
      owner: IT Operations
      addresses: CVE-2026-63436
      evidence: 'Suggested Fix: Apply the same destination-boundary validation used by ZipUtil.unpack(...)'
---

The zt-zip library (prior to 1.18.0) contains a path traversal vulnerability in the `Zips` fluent API. Unlike the standard `ZipUtil.unpack()` method, the `Zips` implementation does not validate that ZIP entry names remain within the configured destination directory. Attackers can leverage ZIP archives containing entries with `../` sequences to write files to arbitrary locations on the filesystem, constrained only by the process's permissions. This issue impacts both the standard unpack flow and transformer-based operations.

## Impact
Successful exploitation allows for arbitrary file writes outside the intended extraction path. This can lead to remote code execution or application state manipulation if an attacker can overwrite sensitive configuration files, scripts, or application binaries within the process's effective scope.

## Recommendation
- Update the `zt-zip` library to version 1.18.0 or later immediately.
- Review applications using `Zips.get(...).unpack().destination(...).process()` to confirm if they process untrusted ZIP archives.
- As an interim measure, ensure the process running the extraction has strictly limited filesystem permissions (Principle of Least Privilege).
