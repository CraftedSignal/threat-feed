---
brief_id: brief-2026-06-langflow-unauthenticated-file-upload-dos-info-leak
event_id: brief-2026-06-langflow-unauthenticated-file-upload-dos-info-leak
revision: 1
activity_at: "2026-06-17T18:47:54Z"
title: Langflow Unauthenticated File Upload Leads to DoS and Information Leak (CVE-2026-55450)
slug: 2026-06-langflow-unauthenticated-file-upload-dos-info-leak
description: An unauthenticated file upload vulnerability, CVE-2026-55450, in Langflow versions prior to 1.9.1 allows remote attackers to upload arbitrary amounts of data to the server via the `/api/v1/upload/{flow_id}` endpoint, leading to disk space exhaustion and Denial-of-Service, additionally leaking the absolute file path in the server's response.
date: "2026-06-17T18:47:54Z"
lastmod: "2026-10-22T08:46:57Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XBLACKASH-CVE-2026-55450&utm_source=rss&utm_medium=rss
tags:
  - denial-of-service
  - unauthenticated-access
  - information-leak
  - web-vulnerability
  - langflow
vendors:
  - Langflow
products:
  - Langflow (< 1.9.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    subtechnique_id: T1592.002
    subtechnique_name: Software
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.001
    subtechnique_name: OS Exhaustion Flood
cves:
  - id: CVE-2026-55450
    cvss: 9.3
    epss: 0.0119
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-x223-p2gf-v735
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55450
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XBLACKASH-CVE-2026-55450&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-55450 Exploitation - Unauthenticated Langflow Upload Attempt
    description: Detects attempts to exploit CVE-2026-55450 by identifying unauthenticated POST requests to the deprecated /api/v1/upload/{flow_id} endpoint in Langflow, indicative of a potential file upload or DoS attack.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1499.001
    data_sources:
      - webserver
  - title: Detects CVE-2026-55450 Exploitation - Successful Unauthenticated Langflow Upload
    description: Detects successful exploitation of CVE-2026-55450 by identifying HTTP 201 Created responses from unauthenticated POST requests to the deprecated /api/v1/upload/{flow_id} endpoint in Langflow, indicating a successful file upload and potential disk exhaustion or information leak.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - impact
      - initial_access
    techniques:
      - T1190
      - T1499.001
      - T1592
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-10-22T08:46:57Z"
    level: L2
    summary: poc_available; added CVE-2026-55450
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XBLACKASH-CVE-2026-55450&utm_source=rss&utm_medium=rss
---

A critical vulnerability, CVE-2026-55450, has been identified in Langflow, affecting all versions prior to 1.9.1. This flaw allows unauthenticated attackers with network access to a Langflow instance to upload files of any size to the server's local filesystem through the deprecated `/api/v1/upload/{flow_id}` endpoint. The vulnerability stems from a lack of authentication and file size validation on this endpoint. Exploitation can lead to severe resource exhaustion, specifically disk space depletion, which results in a Denial-of-Service (DoS) condition for the Langflow application and potentially the host system. Furthermore, the server's response to successful uploads includes the absolute path of the saved file, disclosing sensitive system information that could aid in chaining further attacks. This vulnerability was reported via GitHub Advisory GHSA-x223-p2gf-v735.

## Attack Chain

1.  An unauthenticated attacker identifies a publicly accessible Langflow instance running a vulnerable version (prior to 1.9.1).
2.  The attacker sends an HTTP POST request to the deprecated and unauthenticated `/api/v1/upload/{flow_id}` endpoint (e.g., `http://langflow_host:7860/api/v1/upload/A_VALID_UUID`) using a tool like `curl`.
3.  The request includes a large file as `multipart/form-data`, specified via the `-F "file=@<any_file>"` parameter.
4.  Due to the absence of authentication checks and file size validation on this endpoint, the Langflow application's `save_uploaded_file` function processes and writes the attacker's large file directly to the local filesystem, within a cache directory structure derived from the provided `flow_id`.
5.  The attacker repeatedly performs these large file uploads, consuming increasing amounts of disk space on the Langflow server.
6.  Upon each successful upload, the server returns an HTTP 201 Created status, and the response body contains the absolute path to the newly saved file on the server (e.g., `/Users/ori/Library/Caches/langflow/A_VALID_UUID/filename.txt`).
7.  The continuous and uncontrolled writing of large files leads to the exhaustion of available disk space, resulting in a Denial-of-Service condition for the Langflow application and potentially critical system functions.
8.  The leaked absolute file paths expose details about the server's directory structure, which can be leveraged by the attacker for subsequent reconnaissance or to craft more sophisticated attacks like path traversal or local file inclusion.

## Impact

The primary impact of CVE-2026-55450 is the potential for a complete Denial-of-Service (DoS) for the affected Langflow application and its host system. Unauthenticated attackers can exhaust server disk space by continuously uploading large files, rendering the application inoperable and potentially destabilizing the entire server. Additionally, the vulnerability leads to an information leak, where absolute file paths on the server are disclosed in response to file uploads. While the source does not provide victim numbers or specific targeted sectors, any organization deploying Langflow versions prior to 1.9.1 is at risk of operational disruption and reconnaissance from this flaw. The leaked path information could facilitate further, more targeted attacks.

## Recommendation

*   **Patch CVE-2026-55450 immediately**: Upgrade Langflow installations to version 1.9.1 or later to mitigate the unauthenticated upload and disk exhaustion vulnerabilities.
*   **Deploy the Sigma rules in this brief**: Implement `Detects CVE-2026-55450 Exploitation - Unauthenticated Langflow Upload` and `Detects CVE-2026-55450 Exploitation - Successful Unauthenticated Langflow Upload` into your SIEM to detect attempted and successful exploitation.
*   **Enable comprehensive web server logging**: Ensure detailed HTTP access logs are enabled for the web server hosting Langflow, capturing `cs-method`, `cs-uri-stem`, `sc-status`, and `c-ip` to effectively utilize the detection rules provided.
*   **Monitor disk space utilization**: Implement alerts for critical disk space thresholds on systems hosting Langflow to identify potential DoS attacks.
