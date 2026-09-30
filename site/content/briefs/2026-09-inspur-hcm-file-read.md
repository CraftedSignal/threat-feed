---
title: Arbitrary File Read in Inspur Haiyue HCM Cloud
slug: 2026-09-inspur-hcm-file-read
description: An unauthenticated arbitrary file read vulnerability (CVE-2024-58387) in Inspur Haiyue HCM Cloud allows remote attackers to disclose sensitive system files via the /api/model_report/file/download endpoint.
date: "2026-09-30T22:37:20Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:inspur:haiyue_hcm_cloud:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - arbitrary-file-read
  - directory-traversal
vendors:
  - Inspur
products:
  - Haiyue HCM Cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Unauthenticated remote attackers can exploit this by manipulating the 'index' and 'ext' query parameters to traverse the filesystem and read sensitive system files.
    confidence_band: high
cves:
  - id: CVE-2024-58387
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-58387
rules:
  - title: Detects CVE-2024-58387 Exploitation - Arbitrary File Read
    description: Detects exploitation attempts targeting the Inspur Haiyue HCM Cloud file download endpoint by looking for directory traversal patterns in query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1005
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy WAF rules to block traffic containing path traversal patterns to /api/model_report/file/download
      owner: SOC
      due: 24h
      evidence: CVE-2024-58387 allows unauthenticated path traversal
  hunt_leads:
    - lead: Search web server logs for HTTP 200 responses to the vulnerable endpoint containing path traversal markers
      technique_id: T1005
      data_needed:
        - Web access logs (cs-uri-stem, cs-uri-query, sc-status)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation of the file read vulnerability is observable in web logs.
---

Inspur Haiyue HCM Cloud contains an arbitrary file read vulnerability in the /api/model_report/file/download endpoint. The flaw arises from insufficient validation of user-supplied path parameters, specifically the 'index' and 'ext' query parameters. Unauthenticated remote attackers can leverage this vulnerability to perform directory traversal, allowing them to read arbitrary files from the underlying filesystem. This risk includes the unauthorized disclosure of sensitive information such as /etc/passwd, application database files, and critical system configuration files. Evidence of exploitation in the wild was first reported by the Shadowserver Foundation on November 4, 2024. Given the nature of the vulnerability and the potential for credential harvesting or infrastructure discovery, immediate patching or restriction of access to the HCM cloud interface is recommended for organizations currently running affected versions.

## Attack Chain

1. Attacker performs reconnaissance to identify public-facing instances of Inspur Haiyue HCM Cloud.
2. Attacker probes the /api/model_report/file/download endpoint to test for path traversal vulnerabilities.
3. Attacker crafts a malicious HTTP GET request targeting the /api/model_report/file/download path.
4. Attacker injects traversal sequences into the 'index' and 'ext' parameters (e.g., /api/model_report/file/download?index=/&ext=etc/passwd).
5. The application fails to sanitize the input, resolving the path relative to the root directory.
6. The server returns the contents of the requested file in the HTTP response body.
7. Attacker parses the response to extract sensitive credentials or system configuration data.

## Impact

Successful exploitation allows unauthenticated attackers to gain unauthorized access to sensitive files residing on the server. Potential consequences include the theft of system credentials (e.g., /etc/passwd), database connection strings, API keys, or configuration files that could facilitate further compromise of the internal network and HCM system data.

## Recommendation

1. Prioritize patching or updating Inspur Haiyue HCM Cloud to the version provided by the vendor that addresses CVE-2024-58387.
2. Apply the Sigma rule below to detect exploitation attempts targeting the /api/model_report/file/download endpoint.
3. Restrict access to the HCM Cloud administrative and report endpoints at the network edge to authorized IPs only.
4. Monitor web server logs for HTTP GET requests containing directory traversal sequences (e.g., ../, /etc/passwd) targeting the identified vulnerable endpoint.
