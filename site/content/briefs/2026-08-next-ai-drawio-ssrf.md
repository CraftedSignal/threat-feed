---
title: SSRF Vulnerability in Next AI Draw.io
slug: 2026-08-next-ai-drawio-ssrf
description: Next AI Draw.io versions 0.4.16 and earlier are vulnerable to unauthenticated SSRF via the /api/parse-url endpoint due to incomplete hostname validation.
date: "2026-08-13T19:43:51Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - DayuanJiang
products:
  - next-ai-draw-io
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can supply hostnames that bypass string validation but resolve to internal addresses, allowing them to reach arbitrary internal HTTP services.
    confidence_band: high
cves:
  - id: CVE-2026-72777
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72777
  - https://www.vulncheck.com/advisories/next-ai-draw-io-ssrf-via-dns-rebinding-in-parse-url
rules:
  - title: Detects CVE-2026-72777 Exploitation - SSRF attempt in /api/parse-url
    description: Detects exploitation attempts against the /api/parse-url endpoint by monitoring for POST requests, which are the primary vector for this SSRF vulnerability.
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
    - action: Monitor /api/parse-url for excessive POST requests using provided Sigma rule.
      owner: Detection Engineering
      due: 24h
      evidence: Exploitation via POST /api/parse-url.
  mitigation_plan:
    - priority: immediate
      action: Patch Next AI Draw.io to a version beyond 0.4.16.
      owner: IT Operations
      addresses: CVE-2026-72777
      evidence: NVD vulnerability entry.
---

Next AI Draw.io versions 0.4.16 and earlier contain a server-side request forgery (SSRF) vulnerability in the POST /api/parse-url endpoint. The vulnerability arises because the application performs hostname validation using static string pattern matching rather than resolving the provided input via DNS. This allows an unauthenticated attacker to supply a crafted hostname that bypasses the initial string-based filter but resolves to internal infrastructure addresses upon execution. Successful exploitation enables an attacker to reach arbitrary internal HTTP services, potentially exfiltrating sensitive data, internal service responses, or cloud instance metadata (e.g., AWS/GCP/Azure IMDS). The issue was identified as a security risk where the lack of proper DNS-based validation allows attackers to probe and access resources within the host's internal network segment.

## Impact

Successful exploitation allows unauthenticated remote attackers to perform SSRF attacks against internal network resources. This can result in unauthorized access to internal services, discovery of internal network topology, and the exfiltration of sensitive configuration data or cloud provider metadata. This vulnerability poses a significant risk to organizations running this software in cloud-native environments where internal metadata services are reachable from the application host.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
* Patch the Next AI Draw.io application to a version beyond 0.4.16 as soon as a fix is provided by the maintainer.
* Deploy the Sigma rule below to monitor for exploitation attempts targeting the /api/parse-url endpoint.
* Restrict network access for the server running Next AI Draw.io to prevent it from reaching internal metadata services (e.g., 169.254.169.254) and sensitive internal endpoints.
* Implement egress filtering to limit the application's ability to initiate connections to unauthorized internal IP ranges.
