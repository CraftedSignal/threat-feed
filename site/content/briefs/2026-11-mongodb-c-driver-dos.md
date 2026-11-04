---
brief_id: brief-2026-11-03-mongodb-c-driver-dos
event_id: brief-2026-11-03-mongodb-c-driver-dos
revision: 2
activity_at: "2026-11-04T00:26:49Z"
revision_history:
  - revision: 2
    at: "2026-11-04T00:26:49Z"
    checksum: sha256:60565a57001abf2185ef105c5a9362fb50d6e09748007998c322771d7ce89989
    summary: added coverage for MongoDB C Driver
    changed_fields:
      - action_plan
      - cpes
      - cves
      - lastmod
      - references
      - tags
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120678
title: 'MongoDB C Driver: GridFS file download API denial of service (CVE-2026-120955)'
slug: 2026-11-mongodb-c-driver-dos
description: The MongoDB C Driver fails to validate internal operation results within the GridFS file download API, allowing an attacker to trigger a process crash and service unavailability.
date: "2026-11-03T20:02:43Z"
lastmod: "2026-11-04T00:24:51Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; no IOCs or specific TTP-based detection artifacts available.
cpes:
  - cpe:2.3:a:mongodb:mongo-c-driver:*:*:*:*:*:*:*:*
  - cpe:2.3:a:mongodb:c_driver:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - memory-leak
  - mongodb
vendors:
  - MongoDB
products:
  - MongoDB C Driver
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This can cause the process to terminate when stream operations continue.
    confidence_band: high
cves:
  - id: CVE-2026-120955
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-120678
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120955
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120678
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Identify applications using MongoDB C Driver and prepare for patching.
      owner: IT Operations
      due: 48h
      evidence: The vulnerability exists in the MongoDB C Driver and impacts availability.
    - action: Identify and inventory applications relying on MongoDB C Driver
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects client applications using the library.
  hunt_leads:
    - lead: Monitor application logs for frequent crashes or unexpected termination of processes using the MongoDB C Driver during GridFS operations.
      technique_id: T1499
      data_needed:
        - Application error logs
        - OS system event logs (Windows Event ID 1000, Linux core dumps)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: A user who can influence file download parameters can trigger this condition.
    - lead: Identify applications exhibiting sudden, sustained, or unbounded memory growth (Resident Set Size) correlated with network activity to MongoDB nodes
      technique_id: T1499
      data_needed:
        - Application performance monitoring (APM) metrics
        - System-level memory telemetry (e.g., Linux /proc/[pid]/stat or Windows Process object)
        - Network connection logs to MongoDB endpoints
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The flaw causes repeated, unbounded memory growth when processing compressed server responses.
  mitigation_plan:
    - priority: medium
      action: Update to the patched version of MongoDB C Driver as released by the vendor.
      owner: IT Operations
      addresses: CVE-2026-120955
      evidence: Vulnerability in GridFS file download API.
    - priority: immediate
      action: Upgrade MongoDB C Driver to a version containing the fix for CVE-2026-120678
      owner: IT Operations
      addresses: CVE-2026-120678
      evidence: Vendor patch is the primary remediation for this memory management flaw.
updates:
  - at: "2026-11-04T00:24:51Z"
    level: L2
    summary: added coverage for MongoDB C Driver
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120678
---

The MongoDB C Driver contains a vulnerability in the GridFS file download API where the failure to check the result of internal operations during specific error conditions can lead to process termination. An attacker capable of manipulating file download parameters can induce this condition, causing a denial of service for applications utilizing the affected driver for GridFS operations. There is currently no mention of remote code execution or authentication bypass; the impact is limited to service availability.

## Impact

Successful exploitation results in the termination of the process utilizing the affected MongoDB C Driver API, leading to denial-of-service for the dependent application.

## Recommendation

1. Inventory all applications currently utilizing the MongoDB C Driver.
2. Monitor for application-level crashes or service restarts occurring during GridFS file retrieval operations.
3. Apply patches or updates to the MongoDB C Driver once a remediated version is released by the vendor.
