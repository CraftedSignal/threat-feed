---
title: Langflow Unrestricted File Upload Vulnerability (CVE-2026-6596)
slug: 2026-04-langflow-unrestricted-upload
description: An unrestricted file upload vulnerability in langflow-ai langflow versions up to 1.1.0 allows remote attackers to execute arbitrary code via the create_upload_file function in the API Endpoint.
date: "2026-04-20T03:16:16Z"
type: advisory
types:
  - advisory
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

A critical security vulnerability, identified as CVE-2026-6596, has been discovered in langflow-ai langflow, affecting versions up to 1.1.0. The vulnerability resides within the `create_upload_file` function of the `src/backend/base/Langflow/api/v1/endpoints.py` file, specifically in the API Endpoint component. This flaw allows for unrestricted file uploads, potentially enabling attackers to upload and execute malicious files on the server. The vulnerability is remotely exploitable and an exploit has been publicly released, increasing the risk of widespread exploitation. The vendor was notified, but did not respond.

## Attack Chain

1.  An attacker identifies a Langflow instance running a vulnerable version (<= 1.1.0).
2.  The attacker sends a crafted HTTP POST request to the `create_upload_file` API endpoint.
3.  The request includes a malicious file disguised with a permissible extension or without proper validation.
4.  The `create_upload_file` function fails to adequately validate the uploaded file type or size.
5.  The malicious file is written to the server's file system in an accessible location.
6.  The attacker crafts a second request to execute the uploaded malicious file. This could involve accessing the file directly via a web browser or triggering its execution through other server-side processes.
7.  Successful execution of the file grants the attacker arbitrary code execution on the server.
8.  The attacker leverages code execution to compromise the system, potentially leading to data exfiltration, service disruption, or further lateral movement within the network.

## Impact

Successful exploitation of this vulnerability could allow an attacker to gain complete control over the affected Langflow instance. This could lead to the compromise of sensitive data, disruption of services, and potential further attacks on other systems within the network. Given the ease of exploitation and the availability of a public exploit, organizations using vulnerable versions of Langflow are at significant risk. The impact would depend on the deployment and data handled by the Langflow installation.

## Recommendation

*   Upgrade Langflow to a version higher than 1.1.0 to patch CVE-2026-6596.
*   Implement the Sigma rule `Detect Suspicious File Uploads to Langflow API` to detect exploitation attempts targeting the `create_upload_file` endpoint.
*   Monitor web server logs for suspicious POST requests to the `/api/v1/upload` endpoint, as this is the likely path for exploitation.
