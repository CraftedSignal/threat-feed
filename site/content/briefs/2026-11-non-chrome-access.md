---
brief_id: brief-2026-11-16-non-chrome-access
event_id: brief-2026-11-16-non-chrome-access
revision: 1
activity_at: "2026-11-16T04:19:20Z"
title: Non-Chrome Process Accessing Chrome Default Directory
slug: 2026-11-non-chrome-access
description: The use of non-Chrome processes to access the Chrome user default folder is a technique used by various threats to exfiltrate sensitive data such as credentials and cookies.
date: "2026-11-16T04:19:20Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - FIN7
  - Carbon Spider
  - Sangria Tempest
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    subtechnique_id: T1555.003
    subtechnique_name: Credentials from Web Browsers
    evidence: The Chrome default folder contains sensitive user data such as login credentials, browsing history, and cookies.
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/non_chrome_process_accessing_chrome_default_dir.yml
rules:
  - title: Non Chrome Process Accessing Chrome Default Dir
    description: The following analytic detects a non-Chrome process accessing files in the Chrome user default folder. It leverages Windows Security Event logs, specifically event code 4663, to identify unauthorized access attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.003
    data_sources:
      - object_access
      - windows
      - security
rules_count: 1
---

## Overview

The following analytic detects a non-Chrome process accessing files in the Chrome user default folder. It leverages Windows Security Event logs, specifically event code 4663, to identify unauthorized access attempts. This activity is significant because the Chrome default folder contains sensitive user data such as login credentials, browsing history, and cookies.

## Attack Chain

Malicious actors, including RATs, trojans, and groups such as FIN7, may access the Chrome default directory to exfiltrate sensitive information stored therein. This process involves interacting with files containing credentials or browsing history on the filesystem.

## Impact

If confirmed malicious, this behavior could indicate an attempt to exfiltrate sensitive information, leading to data theft and further compromise of the affected system.

## Recommendation

To successfully implement this detection, you must ingest Windows Security Event logs and track event code 4663. For 4663, enable "Audit Object Access" in Group Policy and check the two boxes listed for both "Success" and "Failure."
