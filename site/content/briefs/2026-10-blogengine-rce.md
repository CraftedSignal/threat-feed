---
title: 'BlogEngine.NET: Arbitrary File Upload Remote Code Execution (CVE-2023-33404)'
slug: 2026-10-blogengine-rce
description: BlogEngine.NET versions 3.3.8.0 and earlier are vulnerable to arbitrary file upload via the /api/upload endpoint, allowing authenticated users with EditOwnPosts permissions to achieve remote code execution.
date: "2026-10-20T09:05:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:blogengine:blogengine.net:*:*:*:*:*:*:*:*
vendors:
  - BlogEngine.NET
products:
  - BlogEngine.NET (<= 3.3.8.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Arbitrary file upload in BlogEngine.NET 3.3.8.0 via /api/upload enables RCE
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Requesting the file that was uploaded leads RCE.
    confidence_band: high
cves:
  - id: CVE-2023-33404
    cvss: 9.8
    epss: 0.25782
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HACIP-CVE-2023-33404&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2023-33404 Exploitation - Unauthorized File Upload
    description: Detects potential exploitation of CVE-2023-33404 by monitoring for POST requests to the /api/upload endpoint, often associated with the action parameter used for video uploads.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Identify and scan all public-facing BlogEngine.NET deployments for versioning
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects versions 3.3.8.0 and earlier
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to block malicious POST requests to /api/upload
      owner: Security Engineering
      addresses: CVE-2023-33404
      evidence: Vulnerability is exploitable via direct HTTP API requests
---

BlogEngine.NET versions 3.3.8.0 and earlier contain an arbitrary file upload vulnerability (CVE-2023-33404) that facilitates remote code execution. The vulnerability resides within the application's API processing logic, specifically the /api/upload endpoint. An attacker holding the 'EditOwnPosts' permission can abuse this endpoint to upload malicious files. The application fails to properly validate the file type or path, instead saving the uploaded content to a hard-coded directory. Once the file is placed in this directory, an attacker can access the file via a standard HTTP request to trigger execution of the embedded code. This vulnerability is significant due to the availability of proof-of-concept exploit material, which increases the likelihood of exploitation against unpatched instances.

## Attack Chain

1. Attacker authenticates to the BlogEngine.NET instance with at least 'EditOwnPosts' privileges.
2. Attacker initiates an HTTP POST request to the /api/upload endpoint with the parameter "action=video".
3. The application verifies the user's 'EditOwnPosts' permissions.
4. The application processes the request, utilizing the hard-coded directory path for storage.
5. The server-side UploadVideo function is invoked to handle the incoming file stream.
6. The application writes the malicious file to the filesystem, creating the target directory if it does not already exist.
7. Attacker makes a subsequent HTTP GET request to the path where the file was saved.
8. The web server executes the code contained within the uploaded file, resulting in full remote code execution.

## Impact

Successful exploitation allows unauthenticated (post-authentication) attackers to gain remote code execution on the server hosting BlogEngine.NET. This grants the attacker the ability to interact with the underlying operating system, potentially leading to full system compromise, data exfiltration, or the deployment of additional malicious payloads.

## Recommendation

1. Identify all instances of BlogEngine.NET running version 3.3.8.0 or earlier within the enterprise environment.
2. Monitor web access logs for POST requests to the /api/upload endpoint originating from user accounts with non-administrative, specific post-editing privileges.
3. Deploy the Sigma rule below to detect potential exploitation attempts targeting the file upload API.
4. Patch all BlogEngine.NET instances to a version later than 3.3.8.0 as soon as vendor updates become available.
