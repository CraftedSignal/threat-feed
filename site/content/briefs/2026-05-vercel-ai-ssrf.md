---
title: Vercel AI Server-Side Request Forgery Vulnerability (CVE-2026-8768)
slug: 2026-05-vercel-ai-ssrf
description: Vulnerability CVE-2026-8768 describes a server-side request forgery (SSRF) flaw in the validateDownloadUrl function of the provider-utils component in Vercel AI versions up to 3.0.97, enabling remote attackers to potentially make internal requests.
date: "2026-05-17T23:18:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - SSRF
  - CVE-2026-8768
  - vercel
  - ai
vendors:
  - Vercel
products:
  - ai (<= 3.0.97)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8768
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8768
  - https://gist.github.com/YLChen-007/07d149bd68adbee58165b4207a2abc71
  - https://gist.github.com/YLChen-007/cf7e47e4dda392f474ca77a66d1d847f
  - https://vuldb.com/submit/811404
  - https://vuldb.com/submit/811405
  - https://vuldb.com/vuln/364393
  - https://vuldb.com/vuln/364393/cti
rules:
  - title: Detect Potential SSRF via validateDownloadUrl
    description: Detects CVE-2026-8768 exploitation - suspicious requests to the /download endpoint with potentially malicious URLs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Suspicious Outbound Connection
    description: Detect outbound connections to internal network ranges from web servers, indicating potential SSRF
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-8768, affects Vercel AI versions up to 3.0.97. The vulnerability resides within the `validateDownloadUrl` function in the `packages/provider-utils/src/download-blob.ts` file of the `provider-utils` component. Successful exploitation allows a remote attacker to potentially force the application to make requests to internal or external resources, potentially leading to information disclosure or other malicious activities. Public exploits for this vulnerability are available. The vendor has been notified but has not responded.

## Attack Chain

1. The attacker identifies the `validateDownloadUrl` function within Vercel AI's `provider-utils` component as a potential SSRF target.
2. The attacker crafts a malicious URL containing a target for the SSRF attack, potentially an internal service or external resource.
3. The attacker injects the malicious URL into an application input that is processed by the vulnerable `validateDownloadUrl` function.
4. The `validateDownloadUrl` function fails to properly sanitize or validate the attacker-controlled URL.
5. The Vercel AI application makes an HTTP request to the attacker-specified URL using server-side resources.
6. The attacker gains access to information from internal services or external resources that the Vercel AI application can access.
7. Depending on the internal services exposed, the attacker might escalate this SSRF to other internal attacks.

## Impact

Successful exploitation of CVE-2026-8768 can allow an attacker to perform actions such as scanning internal networks, reading sensitive files from internal services, or potentially gaining unauthorized access to other systems accessible from the vulnerable Vercel AI instance. The lack of vendor response makes patching uncertain.

## Recommendation

*   Inspect and filter outbound network connections from Vercel AI instances to detect requests to unexpected internal resources (log source: `network_connection`, Sigma rule: "Detect Suspicious Outbound Connection").
*   Deploy the Sigma rule "Detect Potential SSRF via validateDownloadUrl" to identify potential exploitation attempts targeting the vulnerable function.
*   Monitor web server logs for unusual requests containing suspicious URLs indicative of SSRF exploitation attempts (log source: `webserver`).
