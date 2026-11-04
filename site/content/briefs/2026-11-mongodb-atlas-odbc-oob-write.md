---
brief_id: brief-2026-11-04-mongodb-atlas-odbc-oob-write
event_id: brief-2026-11-04-mongodb-atlas-odbc-oob-write
revision: 1
activity_at: "2026-11-04T00:25:52Z"
title: 'MongoDB Atlas SQL ODBC Driver: Out-of-bounds write (CVE-2026-120952)'
slug: 2026-11-mongodb-atlas-odbc-oob-write
description: An out-of-bounds write vulnerability in the MongoDB Atlas SQL ODBC Driver allows a user with basic write privileges to trigger memory corruption and application crashes by manipulating database values retrieved into fixed-width buffers.
date: "2026-11-04T00:25:52Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:mongodb:atlas_sql_odbc_driver:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
  - odbc
vendors:
  - MongoDB
products:
  - Atlas SQL ODBC Driver
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A database user with basic write privileges can influence part of the data written outside the target, which may corrupt memory in the application using the driver and cause that application to terminate unexpectedly.
    confidence_band: high
cves:
  - id: CVE-2026-120952
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120952
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and inventory all applications configured to use the MongoDB Atlas SQL ODBC Driver
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects the driver used by client-side applications
  hunt_leads:
    - lead: Monitor client application logs or system event logs (e.g., Windows Event Viewer Application Log) for frequent process crashes or faults related to the MongoDB ODBC Driver
      technique_id: T1203
      data_needed:
        - Application crash logs
        - System event logs (Event ID 1000/1001 on Windows)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The driver... may corrupt memory in the application using the driver and cause that application to terminate unexpectedly.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied security patches for CVE-2026-120952 as soon as they become available
      owner: IT Operations
      addresses: CVE-2026-120952
      evidence: NVD advisory identifies an OOB write requiring remediation
---

The MongoDB Atlas SQL ODBC Driver contains an out-of-bounds write vulnerability (CVE-2026-120952). The flaw occurs when the driver retrieves database values into fixed-width client-side targets. The driver fails to validate the length of the textual representation of the data against the buffer size before copying, which leads to memory corruption. An attacker with basic database write privileges can influence the data written beyond the buffer boundaries.

## Impact
Successful exploitation can lead to unexpected application termination (Denial of Service) or potential memory corruption within the client application utilizing the driver.

## Recommendation
- Inventory systems and applications utilizing the MongoDB Atlas SQL ODBC Driver.
- Monitor for application crashes or memory access violations involving the MongoDB ODBC Driver components on client-side hosts.
- Contact the vendor for available security patches or updates addressing CVE-2026-120952.
