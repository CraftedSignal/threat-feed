---
title: Path Traversal Vulnerability in Evidently UI
slug: 2026-08-evidently-path-traversal
description: An unauthenticated path traversal vulnerability (CVE-2026-75111) in the Evidently UI dataset materialization endpoint allows attackers to read arbitrary files from the host system.
date: "2026-08-17T22:51:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-75111
  - path-traversal
  - web-application
vendors:
  - EvidentlyAI
products:
  - Evidently (0.7.21)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Evidently UI fails to properly validate the filename parameter in the dataset materialization endpoint, allowing unauthenticated attackers to read arbitrary files outside the workspace directory.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers can supply traversal sequences or absolute paths in the filename field to access system files, which are then materialized into datasets and retrieved through the download endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-75111
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75111
  - https://github.com/evidentlyai/evidently/issues/1887
  - https://www.vulncheck.com/advisories/evidently-ui-path-traversal-via-dataset-materialization-filename
rules:
  - title: Detect CVE-2026-75111 Exploitation - Path Traversal in Dataset Materialization
    description: Detects exploitation of CVE-2026-75111 by searching for path traversal sequences or absolute paths in the filename parameter of dataset materialization requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1210
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Evidently to 0.7.22
      owner: IT Operations
      due: 24h
      evidence: Vendor vulnerability report
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to block path traversal in the /datasets/ endpoint
      owner: SOC
      addresses: CVE-2026-75111
      evidence: Technical assessment of vulnerability
---

Evidently versions 0.7.21 and earlier contain a critical path traversal vulnerability in the UI component. The flaw exists within the dataset materialization logic, specifically in the `filename` parameter, which lacks sufficient input validation. An unauthenticated attacker can supply crafted file paths, including directory traversal sequences (e.g., "../") or absolute filesystem paths, to the dataset materialization endpoint.

When processed, the application attempts to access the specified file outside of the intended workspace directory. The resulting data is then materialized into a dataset, which the attacker can subsequently retrieve via the standard download functionality. This allows for the exfiltration of sensitive system files, configuration data, or other proprietary information accessible to the service process. The issue has been identified in the `data_source.py` module of the Evidently repository.

## Impact

Successful exploitation of this vulnerability enables unauthorized reading of arbitrary files on the host system. This could lead to the exposure of sensitive configuration files, environment variables, source code, or internal application data. Given the unauthenticated nature of the exploit, this vulnerability poses a significant risk to any publicly or internally accessible instances of the Evidently UI.

## Recommendation

* Upgrade to Evidently version 0.7.22 or later immediately to patch the validation logic in the dataset materialization endpoint.
* Restrict access to the Evidently UI service to trusted network segments, ideally requiring VPN or zero-trust authentication until the patch is applied.
* Deploy the detection rule below to identify exploitation attempts targeting the dataset materialization endpoint.
* Audit web server logs for suspicious requests containing path traversal patterns (e.g., ../) targeting the `/datasets/` or materialization-related URI paths.
