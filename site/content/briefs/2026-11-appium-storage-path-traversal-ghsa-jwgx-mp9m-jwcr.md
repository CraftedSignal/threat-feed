---
brief_id: brief-2026-11-20-appium-storage-path-traversal-ghsa-jwgx-mp9m-jwcr
event_id: brief-2026-11-20-appium-storage-path-traversal-ghsa-jwgx-mp9m-jwcr
revision: 1
activity_at: "2026-11-20T20:10:32Z"
title: Appium storage plugin arbitrary file deletion (CVE-2026-58192)
slug: 2026-11-appium-storage-path-traversal-ghsa-jwgx-mp9m-jwcr
description: An unauthenticated path traversal vulnerability in the Appium storage plugin allows remote attackers to perform arbitrary recursive file and directory deletion on the host filesystem.
date: "2026-11-20T20:10:32Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:appium:appium\/storage-plugin:*:*:*:*:*:node.js:*:*
tags:
  - attack.impact
  - attack.t1485
vendors:
  - Appium
products:
  - '@appium/storage-plugin'
product_versions:
  - product: '@appium/storage-plugin'
    range: < 1.1.6
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: An unauthenticated remote client can escape the storage root with ../ sequences and recursively delete arbitrary writable files or directories.
    confidence_band: high
cves:
  - id: CVE-2026-58192
    cvss: 8.6
    epss: 0.00636
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-jwgx-mp9m-jwcr
  - https://cveawg.mitre.org/api/cve/CVE-2026-58192
rules:
  - title: Detect CVE-2026-58192 exploitation - file deletion path traversal
    description: Detects incoming HTTP POST requests to the /storage/delete endpoint containing directory traversal sequences, which indicates exploitation of CVE-2026-58192.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  mitigation_plan:
    - priority: immediate
      action: Upgrade @appium/storage-plugin to 1.1.6 or later
      evidence: This issue is fixed in version 1.1.6.
---

## Overview
The Appium storage plugin is vulnerable to a path traversal flaw in its `POST /storage/delete` endpoint. The vulnerability exists because the `name` parameter is passed directly to `path.join()` and subsequently to `fs.rimraf()` without input sanitization or validation. An unauthenticated attacker can use `../` directory traversal sequences in the `name` parameter to escape the storage root and delete any file or directory that the Appium process user has permission to write. This issue is resolved in version 1.1.6.

## Impact
An attacker can cause significant data loss or denial of service by deleting critical system files, configuration, source code, or SSH keys. The impact is particularly high on CI/CD runners, device farms, and development machines where Appium often runs with elevated privileges.

## Recommendation
Upgrade the `@appium/storage-plugin` package to version 1.1.6 or later immediately. If an immediate upgrade is not possible, restrict access to the Appium HTTP interface to trusted IP addresses only, as the default configuration may expose the service to unauthorized network access.
