---
brief_id: brief-2026-11-02-modem-oob-write
event_id: brief-2026-11-02-modem-oob-write
revision: 2
activity_at: "2026-11-02T17:55:48Z"
revision_history:
  - revision: 2
    at: "2026-11-02T17:55:48Z"
    checksum: sha256:561ccdc0d4632ea4bd16f05b1b56f34984324d0ce22efbd0998db65e0261a107
    summary: added CVE-2026-20585
    changed_fields:
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20585
title: 'Modem: Out-of-bounds write vulnerability (CVE-2026-20499)'
slug: 2026-11-modem-oob-write
description: A missing bounds check in Modem firmware allows an attacker operating a rogue base station to execute an out-of-bounds write, leading to remote privilege escalation without user interaction.
date: "2026-11-02T17:50:14Z"
lastmod: "2026-11-02T17:53:19Z"
type: advisory
claim_state: <nil>
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
  validation_status: Source information is limited to firmware; no specific log-based detection is possible.
cpes:
  - cpe:2.3:a:*:modem:*:*:*:*:*:*:*:*
products:
  - Modem (Patch ID MOLY01857954)
  - 'Modem (Patch ID: MOLY01876662)'
  - Modem
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This could lead to remote escalation of privilege, if a UE has connected to a rogue base station controlled by the attacker, with no additional execution privileges needed.
    confidence_band: high
cves:
  - id: CVE-2026-20499
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-20556
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-20557
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-20585
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20499
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20556
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20557
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20585
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Mobile Security
  immediate_actions:
    - action: Inventory mobile devices and verify firmware versions against vendor updates addressing CVE-2026-20556
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-20556 identified as high severity remote escalation vulnerability
  hunt_leads:
    - lead: Monitor for anomalies in device connectivity, specifically unexpected handovers or base station changes that indicate potential rogue station interaction.
      technique_id: T1566
      data_needed:
        - Device cellular connection logs
        - Base station tower ID changes
      priority: medium
      confidence: medium
      disposition: monitor-only
      evidence: The vulnerability is triggered when a UE has connected to a rogue base station controlled by the attacker.
    - lead: Detect unauthorized or unexpected base station handovers or unusual radio frequency behavior on corporate-issued mobile devices
      technique_id: T1068
      data_needed:
        - Mobile Threat Defense (MTD) logs
        - Base station connection telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation requires a connection to a rogue base station
  mitigation_plan:
    - priority: immediate
      action: Apply firmware patch MOLY01857954 to all vulnerable Modem hardware.
      owner: IT Operations
      addresses: CVE-2026-20499
      evidence: 'Patch ID: MOLY01857954; Issue ID: MSV-8247.'
    - priority: immediate
      action: Apply firmware update MOLY01876662 to affected Modem components
      owner: IT Operations
      addresses: CVE-2026-20556
      evidence: Patch ID provided in source for MSV-9833
updates:
  - at: "2026-11-02T17:50:57Z"
    level: L2
    summary: 'added coverage for Modem (Patch ID: MOLY01876662)'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20556
  - at: "2026-11-02T17:50:58Z"
    level: L2
    summary: added CVE-2026-20557
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20557
  - at: "2026-11-02T17:53:19Z"
    level: L2
    summary: added CVE-2026-20585
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20585
---

CVE-2026-20499 is a memory corruption vulnerability in Modem firmware identified by the lack of bounds checking. The vulnerability allows for remote privilege escalation when a User Equipment (UE) device connects to a rogue base station controlled by an attacker. The vulnerability (MSV-8247) is addressed by Patch ID MOLY01857954.

## Impact

An attacker can achieve remote privilege escalation on a target device without user interaction or prior elevated execution privileges by forcing the device to connect to a malicious base station.

## Recommendation

* Verify the current firmware version of all cellular-connected UEs in the environment.
* Apply patch MOLY01857954 (Issue MSV-8247) to all affected Modem hardware.
* Implement cellular network monitoring to identify anomalies in base station parameters or signal strength characteristics that may indicate rogue base station activity.
