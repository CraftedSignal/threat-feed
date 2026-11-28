---
brief_id: brief-2026-11-28-ryuk-files
event_id: brief-2026-11-28-ryuk-files
revision: 1
activity_at: "2026-11-28T20:43:39Z"
title: 'Ryuk Ransomware: Detection of test file indicators'
slug: 2026-11-ryuk-files
description: This analytic identifies the presence of files containing the keyword Ryuk on the C drive, a common indicator of Ryuk ransomware activity.
date: "2026-11-28T20:43:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic defined based on provided Splunk query.
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: Ryuk ransomware is known for its destructive impact, encrypting critical files and demanding ransom.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/ryuk_test_files_detected.yml
rules:
  - title: Detect Ryuk Ransomware Test Files
    description: Detects the creation of files containing the keyword Ryuk on the C drive, often associated with Ryuk ransomware activity.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Sysmon Event ID 11 and deploy the detection logic to monitor for files containing 'Ryuk' on C drive.
      owner: Detection Engineering
      due: 48h
      evidence: Splunk analytic requirement for Endpoint Filesystem data.
  hunt_leads:
    - lead: Investigate existing file system logs for any files containing 'Ryuk' on the C drive.
      technique_id: T1486
      data_needed:
        - Sysmon Event ID 11
        - Filesystem audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The analytic identifies the presence of files containing the keyword 'Ryuk' in any folder on the C drive.
---

## Overview

The detection identifies files containing the keyword "Ryuk" within the C drive, which is associated with the presence or testing of Ryuk ransomware. Ryuk is a destructive ransomware family that encrypts critical files and demands ransom. Detection leverages filesystem monitoring to identify the creation or existence of these files, which may serve as a precursor to or evidence of malicious activity.

## Impact

Confirmed malicious activity involving Ryuk can lead to significant data loss, operational disruption, and financial damage due to ransom payments and recovery efforts.

## Recommendation

- Deploy filesystem monitoring via Sysmon Event ID 11 to identify files containing the string "Ryuk" on the C drive.
- Use the provided search to investigate the identified file paths and associated processes on affected hosts.
- Evaluate alerts for potential false positives where legitimate files might contain the string "Ryuk" in their filenames.
