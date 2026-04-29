---
title: AVideo Unauthenticated Server-Side Request Forgery Vulnerability
slug: 2024-01-24-avideo-ssrf
description: AVideo versions up to 26.0 are vulnerable to an unauthenticated server-side request forgery (SSRF) vulnerability in the `plugin/Live/test.php` endpoint, allowing attackers to make the server send arbitrary HTTP requests, potentially exposing internal resources and cloud metadata.
date: "2026-03-23T17:16:51Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - ssrf
  - avideo
  - cve-2026-33502
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33502
rules:
  - title: Detect AVideo SSRF Attempt via plugin Live Test
    description: Detects potential SSRF attempts targeting the AVideo plugin/Live/test.php endpoint by looking for suspicious URL parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo SSRF Attempt via Cloud Metadata Access
    description: Detects potential SSRF attempts resulting in access to cloud metadata endpoints.
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

AVideo, an open-source video platform, is affected by a critical unauthenticated Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-33502) in versions up to and including 26.0. The vulnerability exists within the `plugin/Live/test.php` file. An attacker can exploit this flaw to force the AVideo server to make HTTP requests to arbitrary URLs.  Successful exploitation allows attackers to probe internal network services, potentially accessing sensitive internal HTTP resources, cloud metadata endpoints, and other protected assets. The patch for this vulnerability is included in commit 1e6cf03e93b5a5318204b010ea28440b0d9a5ab3. This vulnerability poses a significant risk, as it does not require authentication and can lead to the exposure of sensitive information and potential compromise of internal infrastructure.

## Attack Chain

1.  The attacker identifies an AVideo instance running a vulnerable version (<= 26.0).
2.  The attacker crafts a malicious HTTP request targeting the `plugin/Live/test.php` endpoint.
3.  The crafted request includes a URL parameter pointing to an internal resource (e.g., `http://localhost/admin`).
4.  The AVideo server, without proper validation, processes the request and sends an HTTP request to the attacker-specified URL.
5.  The server receives the HTTP response from the internal resource.
6.  The server may return the content of the internal resource to the attacker, depending on the AVideo application logic.
7.  The attacker analyzes the returned content, potentially gaining access to sensitive information like configuration files, API keys, or internal service endpoints.
8.  The attacker leverages the exposed information to further compromise the AVideo instance or the internal network.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-33502) can lead to the exposure of sensitive internal resources, including configuration files, API keys, and cloud metadata.  This can enable attackers to gain unauthorized access to internal systems, escalate privileges, and potentially compromise the entire infrastructure. The number of affected AVideo instances is currently unknown, but given its open-source nature, it is potentially widespread across various sectors. A successful attack can lead to data breaches, service disruption, and reputational damage.

## Recommendation

*   Upgrade AVideo instances to a patched version containing commit 1e6cf03e93b5a5318204b010ea28440b0d9a5ab3 to remediate CVE-2026-33502.
*   Deploy the Sigma rule `Detect AVideo SSRF Attempt via plugin Live Test` to identify potential exploitation attempts targeting the vulnerable endpoint.
*   Implement network segmentation to restrict access to internal resources and mitigate the impact of successful SSRF exploitation.
*   Review webserver logs for suspicious requests to `plugin/Live/test.php` with unusual URL parameters (log source: webserver).
