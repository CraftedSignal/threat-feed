---
title: Huimeicloud hm_editor Server-Side Request Forgery Vulnerability (CVE-2026-5346)
slug: 2026-04-huimeicloud-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in huimeicloud hm_editor up to version 2.2.3, allowing remote attackers to manipulate the 'url' argument in the client.get function of src/mcp-server.js to potentially access internal resources.
date: "2026-04-02T15:16:53Z"
severities:
  - medium
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

A server-side request forgery (SSRF) vulnerability has been identified in huimeicloud hm_editor, specifically affecting versions up to 2.2.3. The vulnerability resides within the `client.get` function in the `src/mcp-server.js` file, which is part of the image-to-base64 endpoint. By manipulating the `url` argument, a remote attacker can potentially force the server to make requests to unintended locations, including internal resources. This vulnerability, identified as CVE-2026-5346, has a CVSS…
