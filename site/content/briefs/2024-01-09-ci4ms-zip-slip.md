---
title: CI4MS Backup Restore Zip Slip Vulnerability Leads to RCE
slug: 2024-01-09-ci4ms-zip-slip
description: The CI4MS Backup restore function is vulnerable to Zip Slip, allowing remote code execution by uploading a malicious ZIP archive that writes PHP files to the public web root due to missing validation of entry names during extraction, affecting versions prior to 0.31.5.0.
date: "2026-04-22T17:28:39Z"
severities:
  - critical
tags:
  - zip-slip
  - rce
  - code-injection
  - vulnerability
vendors:
  - composer
products:
  - ci4-cms-erp/ci4ms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-xp9f-pvvc-57p4
rules:
  - title: Detect CI4MS Zip Slip via Web Request
    description: Detects potential Zip Slip exploitation attempts in CI4MS by monitoring POST requests to the /backend/backup/restore endpoint with a ZIP archive containing directory traversal sequences.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1068
      - T1566
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Creation via CI4MS Upload
    description: Detects creation of PHP files in web-accessible directories after backup restore, indicating potential RCE exploitation.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - persistence
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A Zip Slip vulnerability exists in the CI4MS backup restore functionality. Authenticated users with backup creation permissions can exploit this by uploading a specially crafted ZIP archive. The vulnerability lies in the `Backup::restore` function (modules/Backup/Controllers/Backup.php), where the application extracts the uploaded ZIP without proper validation of the entry names. This allows an attacker to write files to arbitrary locations, including the public web root, leading to remote code…
