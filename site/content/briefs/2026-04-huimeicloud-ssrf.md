---
title: Huimeicloud hm_editor Server-Side Request Forgery Vulnerability (CVE-2026-5346)
slug: 2026-04-huimeicloud-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in huimeicloud hm_editor up to version 2.2.3, allowing remote attackers to manipulate the 'url' argument in the client.get function of src/mcp-server.js to potentially access internal resources.
date: "2026-04-02T15:16:53Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-5346
  - ssrf
  - huimeicloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5346
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5346
  - https://github.com/wing3e/public_exp/issues/11
  - https://vuldb.com/submit/781341
  - https://vuldb.com/vuln/354701
  - https://vuldb.com/vuln/354701/cti
rules:
  - title: Detect SSRF Attempt in huimeicloud hm_editor
    description: Detects potential Server-Side Request Forgery (SSRF) attempts in huimeicloud hm_editor by monitoring requests to the image-to-base64 endpoint with suspicious URLs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1021.001
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect hm_editor SSRF Attempt with Encoded URL
    description: Detects SSRF attempts against the hm_editor image-to-base64 endpoint using a base64 encoded URL.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1021.001
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability has been identified in huimeicloud hm_editor, specifically affecting versions up to 2.2.3. The vulnerability resides within the `client.get` function in the `src/mcp-server.js` file, which is part of the image-to-base64 endpoint. By manipulating the `url` argument, a remote attacker can potentially force the server to make requests to unintended locations, including internal resources. This vulnerability, identified as CVE-2026-5346, has a CVSS v3.1 score of 7.3 and is remotely exploitable. Public exploits are available. The vendor was notified but has not responded.

## Attack Chain

1.  The attacker identifies an instance of huimeicloud hm_editor running version 2.2.3 or earlier.
2.  The attacker crafts a malicious URL containing a payload designed to exploit the SSRF vulnerability in the image-to-base64 endpoint.
3.  The attacker sends a request to the vulnerable endpoint (`src/mcp-server.js`) with the crafted `url` parameter.
4.  The `client.get` function processes the attacker-controlled `url` argument without proper validation.
5.  The server-side application initiates an HTTP request based on the manipulated URL, potentially targeting internal resources or external services.
6.  The server receives the response from the targeted resource.
7.  The server may process and return the data obtained from the targeted resource to the attacker or use it internally.
8.  The attacker gains unauthorized access to internal information or leverages the server as a proxy for further attacks.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-5346) can lead to unauthorized access to internal resources, sensitive data exposure, and the ability to use the vulnerable server as a proxy for further attacks. The impact includes potential compromise of internal systems, circumvention of security controls, and data breaches. The affected component is the `image-to-base64` endpoint, which may be used to process user-supplied images.

## Recommendation

*   Apply input validation and sanitization to the `url` argument passed to the `client.get` function within the `src/mcp-server.js` file to prevent SSRF attacks, mitigating CVE-2026-5346.
*   Monitor web server logs for suspicious requests targeting the image-to-base64 endpoint (`src/mcp-server.js`) with unusual `url` parameters, using the provided Sigma rule to identify exploitation attempts.
*   Implement network segmentation to limit the impact of successful SSRF attacks by restricting access to internal resources from the vulnerable server.
*   Deploy the Sigma rule to detect attempts to exploit CVE-2026-5346, focusing on unusual URLs being passed to the `image-to-base64` endpoint.
