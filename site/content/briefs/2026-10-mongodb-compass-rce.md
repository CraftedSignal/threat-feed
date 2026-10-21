---
brief_id: brief-2026-10-21-mongodb-compass-rce
event_id: brief-2026-10-21-mongodb-compass-rce
revision: 1
activity_at: "2026-10-21T19:59:06Z"
title: 'MongoDB Compass: Arbitrary code execution via crafted BSON values (CVE-2026-113870)'
slug: 2026-10-mongodb-compass-rce
description: MongoDB Compass is vulnerable to arbitrary code execution when processing specially crafted BSON values from a stored view aggregation pipeline during an editing operation.
date: "2026-10-21T19:59:06Z"
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
  validation_status: Source verified
cpes:
  - cpe:2.3:a:mongodb:compass:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - mongodb
vendors:
  - MongoDB
products:
  - Compass
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: When a user connects to a MongoDB deployment containing a specially crafted view and opens that view for editing, the values can cause arbitrary code to execute with the privileges of the user running Compass.
    confidence_band: high
cves:
  - id: CVE-2026-113870
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113870
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch or upgrade MongoDB Compass to the version containing the fix for CVE-2026-113870.
      owner: IT Operations
      due: 72h
      evidence: Vulnerability CVE-2026-113870
  mitigation_plan:
    - priority: immediate
      action: Advise users to avoid opening views from untrusted or public MongoDB databases within Compass.
      owner: SOC
      addresses: CVE-2026-113870
      evidence: Exploitation occurs when user opens a specially crafted view for editing
---

CVE-2026-113870 affects MongoDB Compass when converting a stored view aggregation pipeline into an editable source format. The vulnerability stems from improper escaping of BSON values, allowing for arbitrary code execution with the privileges of the application user. Exploitation requires an attacker to successfully store a malicious view within a MongoDB deployment and subsequently entice an authorized user to open that view for editing using Compass.

## Impact

Successful exploitation results in arbitrary code execution on the host machine running MongoDB Compass. The impact is limited by the permissions of the local user running the application.

## Recommendation

- Inventory all systems running MongoDB Compass and prepare for updates to the version patched for CVE-2026-113870.
- Advise database administrators and developers to exercise caution when opening or editing views in shared or untrusted MongoDB environments.
