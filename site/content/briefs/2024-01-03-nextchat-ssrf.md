---
title: ChatGPTNextWeb NextChat SSRF Vulnerability (CVE-2026-7178)
slug: 2024-01-03-nextchat-ssrf
description: ChatGPTNextWeb NextChat versions up to 2.16.1 are vulnerable to server-side request forgery (SSRF) due to improper input validation in the storeUrl function, allowing remote attackers to potentially access internal resources or conduct other malicious activities.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - ssrf
  - cve
  - vulnerability
  - web-application
vendors:
  - ChatGPTNextWeb
products:
  - NextChat
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7178
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7178
rules:
  - title: NextChat SSRF Attempt
    description: Detects potential SSRF attempts against ChatGPTNextWeb NextChat by monitoring requests to the /api/artifacts endpoint with suspicious ID parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: NextChat Internal IP Access via SSRF
    description: Detects potential SSRF abuse by monitoring access to private IP ranges from the NextChat server.
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

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-7178, affects ChatGPTNextWeb NextChat versions up to 2.16.1. The vulnerability resides in the `storeUrl` function within the `app/api/artifacts/route.ts` file, specifically related to the Artifacts Endpoint component. An attacker can manipulate the `ID` argument to force the server to make requests to arbitrary internal or external resources. This issue was reported to the project maintainers but remains unpatched. The availability of a public exploit increases the risk of active exploitation. This vulnerability allows attackers to bypass network access controls, potentially accessing sensitive data or internal services.

## Attack Chain

1. The attacker identifies an instance of ChatGPTNextWeb NextChat running a version up to 2.16.1.
2. The attacker crafts a malicious HTTP request targeting the `/api/artifacts` endpoint.
3. The request includes a manipulated `ID` parameter within the request body or query string of the HTTP request to `storeUrl` function.
4. The `storeUrl` function, lacking proper input validation, uses the attacker-supplied `ID` to construct a URL.
5. The NextChat server initiates an HTTP request to the attacker-controlled URL.
6. Depending on the crafted URL, the server may access internal resources, external websites, or cloud services.
7. The server receives the response from the target resource.
8. The attacker leverages the SSRF vulnerability to read sensitive internal data, interact with internal services, or potentially pivot to other internal systems.

## Impact

Successful exploitation of CVE-2026-7178 allows an attacker to perform unauthorized actions within the network where the NextChat server is deployed. This may include reading internal files, accessing other internal applications or services, or potentially escalating privileges if the targeted internal service has its own vulnerabilities. Given the publicly available exploit, organizations using vulnerable versions of NextChat are at increased risk.

## Recommendation

*   Upgrade ChatGPTNextWeb NextChat to a version greater than 2.16.1 to remediate CVE-2026-7178.
*   Deploy the Sigma rule "NextChat SSRF Attempt" to detect suspicious requests to the `/api/artifacts` endpoint with potentially malicious `ID` parameters.
*   Monitor web server logs for outbound connections originating from the NextChat server to unusual or internal IP addresses and domains.
*   Implement strict input validation on the `ID` parameter of the `storeUrl` function if immediate patching is not possible.
