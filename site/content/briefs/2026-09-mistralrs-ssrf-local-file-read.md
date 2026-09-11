---
title: Unauthenticated SSRF and Local File Enumeration in mistral.rs
slug: 2026-09-mistralrs-ssrf-local-file-read
description: The mistralrs-server-core component allows unauthenticated attackers to perform SSRF and enumerate local files via unvalidated image_url and audio_url message parameters.
date: "2026-09-11T00:54:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - file-enumeration
  - denial-of-service
  - webserver
vendors:
  - mistral.rs
products:
  - mistralrs-server-core (<= 0.8.17)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The server is unauthenticated by default and fetches any request-supplied image/audio URL.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1566
    technique_name: Phishing
    evidence: The loader also opens a request-supplied file:// URL or any existing local path, giving an unauthenticated file-existence and file-type oracle.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-wfgq-w7cq-qj7j
rules:
  - title: Detect Attempted SSRF via mistral.rs API
    description: Detects suspicious attempts to pass file paths or non-HTTP protocols into the chat completion API image_url parameter.
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
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update mistralrs-server-core to a version exceeding 0.8.17
      owner: IT Operations
      due: 24h
      evidence: Source states versions <= 0.8.17 are vulnerable
  hunt_leads:
    - lead: Search logs for unusual file paths or internal IP addresses in POST request bodies directed at /v1/chat/completions
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documents exploitation via arbitrary local file existence enumeration
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound network access from the mistral.rs service container to internal subnets and metadata IPs
      owner: IT Operations
      addresses: SSRF primitive via internal network probe
      evidence: Source confirms SSRF end-to-end to internal services
---

The mistral.rs project contains a critical vulnerability in the `mistralrs-server-core` crate (versions 0.8.17 and earlier) that exposes server infrastructure to SSRF and filesystem enumeration. During chat completion requests, the server uses a `parse_image_url` and `parse_audio_url` utility to process media URLs. This utility fails to perform any host validation or IP allowlisting, allowing remote, unauthenticated attackers to supply `http(s)` URLs that resolve to internal network addresses or cloud metadata services. 

Furthermore, the parser accepts `file://` schemes or bare file paths. If a path exists on the local filesystem, the server attempts to open and process it. Because the server returns distinct error messages for valid vs. nonexistent paths, attackers can use the application as an oracle to enumerate the existence and type of files on the server. The vulnerability also enables resource exhaustion (Denial of Service) due to the lack of request timeouts and file size limits during the fetching and reading process.

## Attack Chain

1. Attacker sends a crafted POST request to the `/v1/chat/completions` endpoint.
2. The request includes a `messages` object containing a malicious `image_url` or `audio_url` field.
3. The `mistralrs-server-core` backend passes this unvalidated string to `parse_image_url` or `parse_audio_url`.
4. For SSRF: The backend uses `reqwest::get` to fetch the attacker-supplied URL, following redirects to internal or cloud-metadata destinations.
5. For File Enumeration: The backend attempts `File::open` on the provided string; success confirms file existence, triggering an image decoding error.
6. The server returns a specific HTTP 500 error response reflecting the outcome of the filesystem operation.
7. The attacker parses the error response to confirm file existence or probe internal network services.

## Impact

Successful exploitation allows unauthenticated attackers to probe internal networks, including sensitive cloud metadata services, and enumerate files on the host filesystem. While actual file content disclosure is not directly achieved, the existence oracle provides significant information for lateral movement or further exploitation. Additionally, the lack of input constraints enables a Denial of Service attack by forcing the server to process oversized files or hang on non-responsive internal network requests.

## Recommendation

1. Update `mistralrs-server-core` to a version that implements input validation and restricts media loading.
2. Implement strict allowlists for media domains and block access to private/loopback/link-local IP ranges and cloud metadata services.
3. Deploy web application firewall (WAF) rules to inspect `image_url` and `audio_url` parameters for `file://` schemes or suspicious local file paths (e.g., `/etc/`, `C:\`).
4. Ensure appropriate resource limits and timeouts are configured for the request-handling service to mitigate potential Denial of Service exploitation.
