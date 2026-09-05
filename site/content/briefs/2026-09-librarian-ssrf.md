---
title: Librarian PDF Save Endpoint SSRF Vulnerability (CVE-2024-54819)
slug: 2026-09-librarian-ssrf
description: An authenticated Server-Side Request Forgery (SSRF) vulnerability in the Librarian PDF save endpoint allows attackers to perform unauthorized requests against internal network resources.
date: "2026-09-05T01:15:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - web-vulnerability
  - librarian
  - cve-2024-54819
products:
  - Librarian (3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Librarian application's PDF save endpoint is vulnerable via weak validation of the remote_url parameter.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The SSRF vulnerability allows an attacker to interact with internal network resources by abusing the PDF generation service.
    confidence_band: high
cves:
  - id: CVE-2024-54819
    cvss: 9.1
    epss: 0.18033
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-PARTYWAVESEC-CVE-2024-54819
rules:
  - title: Detects CVE-2024-54819 Exploitation - SSRF via remote_url parameter
    description: Detects HTTP POST requests to the Librarian PDF save endpoint with internal IP addresses in the remote_url parameter, indicative of SSRF exploitation.
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review web server logs for indicators of SSRF against /librarian/index.php/pdf/save
      owner: SOC
      due: 24h
      evidence: Source document identifies the endpoint and parameters used for exploitation
  hunt_leads:
    - lead: Search for HTTP POST requests to Librarian PDF save endpoint with private IP address ranges in the remote_url parameter
      technique_id: T1190
      data_needed:
        - Web server logs containing query strings
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source provides explicit example of a malicious POST request structure
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound network access for the server hosting the Librarian application to only required external endpoints
      owner: IT Operations
      addresses: CVE-2024-54819
      evidence: The vulnerability is an SSRF vector which can be mitigated by egress filtering
  gaps:
    - Lack of vendor-provided patch information
---

CVE-2024-54819 is a high-severity vulnerability (CVSS 9.1) affecting the Librarian application, specifically within the PDF generation module. The flaw exists due to insufficient validation of the 'remote_url' parameter when the application processes PDF save requests. An attacker with valid credentials can manipulate this parameter to force the server to initiate arbitrary HTTP requests to internal network segments, effectively acting as an SSRF vector. 

This vulnerability was disclosed with proof-of-concept exploit code demonstrating how to leverage the 'remote_url' field in conjunction with valid authentication cookies and a CSRF token. By bypassing input validation, attackers can probe internal services or interact with locally hosted applications that are otherwise inaccessible from the public internet. Organizations using Librarian should audit their access logs for unusual POST requests to the PDF save endpoint, particularly those containing non-standard or internal URLs in the 'remote_url' field.

## Attack Chain

1. Attacker performs credential harvesting or utilizes valid account access to gain an authenticated session for the Librarian application.
2. Attacker obtains a valid session cookie (e.g., IL=[COOKIE]) and current CSRF token from the application's authenticated session.
3. Attacker targets the `/librarian/index.php/pdf/save` endpoint to initiate a PDF generation request.
4. Attacker crafts a malicious HTTP POST request, supplying an internal IP address or internal hostname within the 'remote_url' parameter.
5. The Librarian server receives the POST request and fails to sanitize the 'remote_url' input.
6. The server-side service initiates an outbound request to the target URI specified by the attacker, effectively performing SSRF.
7. Attacker receives information or state changes from the internal resource, facilitating further lateral movement or data exfiltration.

## Impact

Successful exploitation of this SSRF vulnerability grants an authenticated attacker the ability to bypass network segmentation and interact with internal-only services or APIs. This could lead to the exposure of sensitive internal data, exploitation of secondary internal vulnerabilities, or administrative access to other internal systems.

## Recommendation

1. Monitor web server logs for HTTP POST requests to `/librarian/index.php/pdf/save` that exhibit suspicious 'remote_url' parameters, such as internal IP addresses (e.g., 127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
2. Deploy the provided Sigma rule to detect attempts at exploiting the endpoint.
3. Implement strict allow-listing for the 'remote_url' parameter on the server side to ensure only trusted, external domains are reachable.
4. Ensure that the web server running Librarian is appropriately firewalled to minimize the impact of SSRF if this vulnerability is present.
