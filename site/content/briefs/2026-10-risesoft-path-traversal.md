---
title: Path Traversal Vulnerability in Risesoft Digital-Infrastructure
slug: 2026-10-risesoft-path-traversal
description: Risesoft Digital-Infrastructure versions 9.6.5 through 9.6.11 contain a path traversal vulnerability in the fileManager component, allowing unauthenticated attackers to read sensitive files via the /rest/retrieveFileStream endpoint.
date: "2026-10-13T18:37:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:risesoft:digital-infrastructure:9.6.5:*:*:*:*:*:*:*
  - cpe:2.3:a:risesoft:digital-infrastructure:9.6.11:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - path-traversal
  - credential-exposure
vendors:
  - Risesoft
products:
  - Digital-Infrastructure (9.6.5-9.6.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can request the unauthenticated /rest/retrieveFileStream endpoint to retrieve files like application.yml
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers can request the unauthenticated /rest/retrieveFileStream endpoint to retrieve files like application.yml, exposing database, Redis and Nacos credentials.
    confidence_band: high
cves:
  - id: CVE-2026-110115
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110115
rules:
  - title: Detect CVE-2026-110115 Path Traversal Exploitation
    description: Detects exploitation attempts against Risesoft Digital-Infrastructure by searching for path traversal sequences in the /rest/retrieveFileStream endpoint
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Risesoft Digital-Infrastructure to a version beyond 9.6.11
      owner: IT Operations
      due: 48h
      evidence: Source states versions 9.6.5 through 9.6.11 are vulnerable
  hunt_leads:
    - lead: Search web logs for 200/206 status codes in response to /rest/retrieveFileStream requests
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows retrieval of files; successful requests indicate potential breach
---

Risesoft Digital-Infrastructure versions 9.6.5 through 9.6.11 contain a path traversal vulnerability in the Y9FileController.retrieveFileStream handler within the fileManager component. This vulnerability stems from improper validation of user-supplied input in the fullPath and fileName parameters, allowing unauthenticated attackers to escape the intended directory scope. By sending crafted HTTP GET requests to the /rest/retrieveFileStream endpoint, an attacker can access arbitrary files on the underlying filesystem. This flaw poses a significant risk, as it enables the retrieval of sensitive configuration files such as application.yml. Successful exploitation results in the exposure of database, Redis, and Nacos credentials, which could lead to further unauthorized access, data exfiltration, or complete compromise of the backend infrastructure.

## Impact

Successful exploitation allows unauthenticated attackers to read any file on the server accessible to the application process. In enterprise environments, this typically leads to the theft of environment configuration files containing clear-text credentials for database, Redis, and Nacos instances. This exposure can facilitate lateral movement within the network and potential compromise of the entire application deployment.

## Recommendation

* Patch Risesoft Digital-Infrastructure to the latest version available after 9.6.11 immediately.
* Monitor web server logs for requests to the /rest/retrieveFileStream endpoint containing path traversal sequences (e.g., ../ or ..\).
* Enforce strict input validation on all application parameters that influence file path construction.
* Review logs for unauthorized access patterns specifically targeting configuration files like application.yml.
