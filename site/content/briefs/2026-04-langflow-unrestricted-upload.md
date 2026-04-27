---
title: Langflow Unrestricted File Upload Vulnerability (CVE-2026-6596)
slug: 2026-04-langflow-unrestricted-upload
description: An unrestricted file upload vulnerability in langflow-ai langflow versions up to 1.1.0 allows remote attackers to execute arbitrary code via the create_upload_file function in the API Endpoint.
date: "2026-04-20T03:16:16Z"
severities:
  - high
tags:
  - CVE-2026-6596
  - unrestricted-upload
  - langflow
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6596
  - https://gist.github.com/chenhouser2025/c2aabfdee41009cfe45d28a9924742a0
  - https://vuldb.com/vuln/358231
rules:
  - title: Detect Suspicious File Uploads to Langflow API
    description: Detects suspicious POST requests to the Langflow API upload endpoint, indicative of potential exploitation of CVE-2026-6596.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Extension Uploaded to Langflow
    description: Detects file uploads with suspicious file extensions like .php, .exe, .sh, etc.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security vulnerability, identified as CVE-2026-6596, has been discovered in langflow-ai langflow, affecting versions up to 1.1.0. The vulnerability resides within the `create_upload_file` function of the `src/backend/base/Langflow/api/v1/endpoints.py` file, specifically in the API Endpoint component. This flaw allows for unrestricted file uploads, potentially enabling attackers to upload and execute malicious files on the server. The vulnerability is remotely exploitable and an…
