---
title: WWBN AVideo Unauthenticated Remote Denial of Service Vulnerability
slug: 2024-01-24-avideo-dos
description: WWBN AVideo versions up to 26.0 are vulnerable to a denial-of-service attack where unauthenticated remote attackers can exhaust disk space by sending arbitrary POST data to a specific endpoint.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - avideo
  - denial-of-service
  - webserver
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33483
rules:
  - title: Detect AVideo Excessive TMP File Creation
    description: Detects a large number of temporary files being created by the AVideo webserver process in the /tmp/ directory, indicating a potential denial-of-service attempt.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - file_event
      - linux
  - title: Detect AVideo POST Request to Chunk Endpoint
    description: Detects POST requests to the aVideoEncoderChunk.json.php endpoint which is vulnerable to DoS.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is susceptible to a denial-of-service (DoS) vulnerability (CVE-2026-33483) in versions up to and including 26.0. The vulnerability lies in the `aVideoEncoderChunk.json.php` endpoint, a standalone PHP script lacking authentication, framework includes, and resource limits. An unauthenticated attacker can exploit this by sending arbitrary POST data to this endpoint, leading to the creation of persistent temporary files in the `/tmp/` directory. The absence of size caps, rate limiting, and cleanup mechanisms allows attackers to rapidly exhaust disk space, causing a denial of service for the entire server. This vulnerability can be addressed by applying the patch included in commit 33d1bae6c731ef1682fcdc47b428313be073a5d1.

## Attack Chain

1.  The attacker identifies a vulnerable AVideo instance running a version up to 26.0.
2.  The attacker crafts a malicious HTTP POST request containing arbitrary data.
3.  The attacker sends the crafted POST request to the `aVideoEncoderChunk.json.php` endpoint on the target server.
4.  The AVideo server receives the request and, due to the lack of authentication, processes it without verification.
5.  The `aVideoEncoderChunk.json.php` script writes the arbitrary POST data to a temporary file in the `/tmp/` directory.
6.  The attacker repeats steps 2-5, sending a large number of POST requests to rapidly fill the `/tmp/` directory.
7.  The `/tmp/` directory becomes full, preventing the server from writing other necessary temporary files.
8.  The server experiences a denial of service due to the disk space exhaustion, impacting all services reliant on disk I/O.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition affecting the entire AVideo server. This can result in the website becoming unavailable to users, disrupting video streaming services, and potentially impacting other applications reliant on the same server. Given the ease of exploitation, a single attacker could potentially bring down a vulnerable AVideo instance with minimal effort, leading to significant disruption of video services. The number of victims will depend on the prevalence of unpatched AVideo instances.

## Recommendation

*   Apply the patch from commit 33d1bae6c731ef1682fcdc47b428313be073a5d1 to address the vulnerability in `aVideoEncoderChunk.json.php`.
*   Deploy the Sigma rule `Detect AVideo Excessive TMP File Creation` to monitor for suspicious activity in the `/tmp/` directory related to AVideo processes.
*   Implement rate limiting on the `aVideoEncoderChunk.json.php` endpoint to prevent attackers from overwhelming the server with requests.
*   Monitor web server logs for excessive POST requests to `aVideoEncoderChunk.json.php` and investigate any anomalies.
