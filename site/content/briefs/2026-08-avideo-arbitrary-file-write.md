---
title: Unauthenticated Arbitrary File Write in AVideo
slug: 2026-08-avideo-arbitrary-file-write
description: An unauthenticated arbitrary file write vulnerability (CVE-2026-72748) in the AVideo aVideoEncoderChunk.json.php endpoint allows remote attackers to upload arbitrary content to the server, potentially leading to remote code execution.
date: "2026-08-11T14:02:13Z"
lastmod: "2026-08-11T14:03:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - rce
  - file-write
  - cve-2026-72748
  - web-application
  - xss
  - injection
vendors:
  - WWBN
products:
  - AVideo (29.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: AVideo contains an unauthenticated arbitrary file write vulnerability in the aVideoEncoderChunk.json.php endpoint that allows remote attackers to write up to 4 GB of arbitrary content to the server filesystem.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: 'Endpoint Denial of Service: Disk Exhaustion'
    evidence: Attackers can exhaust disk space causing denial of service
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: executing the injected script in the admin's browser session
    confidence_band: high
cves:
  - id: CVE-2026-72748
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72748
  - https://github.com/WWBN/AVideo/security/advisories/GHSA-v7p7-jccx-h37c
  - https://www.vulncheck.com/advisories/avideo-unauthenticated-arbitrary-file-write-via-avideoencoderchunk-json-php
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72747
  - https://github.com/WWBN/AVideo/security/advisories/GHSA-cfvq-r985-84wj
  - https://github.com/WWBN/AVideo/commit/1adcb75458a3b31058655698a833e8cbde4d0593
rules:
  - title: Detect CVE-2026-72748 Exploitation Attempt
    description: Detects unauthenticated HTTP PUT requests to the aVideoEncoderChunk.json.php endpoint
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-72747 Exploitation - XSS via Registration Phone Field
    description: Detects potential exploitation attempts where a script tag is injected into the phone field during AVideo user registration.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
    - IT Operations
  immediate_actions:
    - action: Deploy WAF rule to block PUT requests to /aVideoEncoderChunk.json.php
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-72748 allows unauthenticated remote file write
  mitigation_plan:
    - priority: immediate
      action: Patch AVideo to the version provided in the GitHub commit
      owner: IT Operations
      addresses: CVE-2026-72748
      evidence: Vendor security advisory GHSA-v7p7-jccx-h37c
updates:
  - at: "2026-08-11T14:03:21Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-72747 Exploitation - XSS via Registration Phone Field'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72747
---

AVideo, an open-source video platform, contains a critical vulnerability (CVE-2026-72748) in the `aVideoEncoderChunk.json.php` endpoint. This vulnerability allows remote, unauthenticated attackers to perform an arbitrary file write to the server's filesystem using HTTP PUT requests. The flaw permits the upload of files up to 4 GB in size. This can be used by attackers to exhaust server disk space (causing a denial-of-service condition), poison the video encoding pipeline, or, if chained with local file inclusion (LFI) vulnerabilities, achieve remote code execution. Defenders should prioritize patching or restricting access to the affected endpoint immediately.

## Attack Chain

1. Attacker identifies an AVideo instance reachable over the network.
2. Attacker probes the target for the presence of the `aVideoEncoderChunk.json.php` endpoint.
3. Attacker sends a crafted HTTP PUT request to the target endpoint without providing authentication credentials.
4. The vulnerable endpoint accepts the payload, writing it to the server's local filesystem.
5. Attacker iterates the request to maximize disk space usage, inducing a denial-of-service state.
6. Attacker overwrites existing application logic or uploads a web shell to the server.
7. Attacker executes the uploaded payload to gain arbitrary code execution on the underlying host.

## Impact

Successful exploitation of CVE-2026-72748 can result in total compromise of the AVideo server. Potential impacts include complete loss of availability through disk exhaustion, unauthorized data modification via pipeline poisoning, and full system takeover via remote code execution. Organizations using AVideo version 29.0 and below are susceptible to these risks.

## Recommendation

- Update AVideo to the latest patched version available from the WWBN repository to remediate CVE-2026-72748.
- Apply the vendor-provided security patch immediately: https://github.com/WWBN/AVideo/commit/1b55a9b3c4911d2f31594ce2e60566c70c6b95e8
- Monitor web server logs for HTTP PUT requests targeting `aVideoEncoderChunk.json.php` from unauthorized or unexpected IP addresses.
- Restrict access to the `aVideoEncoderChunk.json.php` endpoint at the web application firewall (WAF) or ingress proxy level to authenticated users only.
