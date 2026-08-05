---
title: SSRF Vulnerability in Open WebUI via NAT64-encoded URLs
slug: 2026-08-open-webui-ssrf
description: Authenticated users can bypass SSRF protection in Open WebUI by wrapping internal IPv4 addresses in NAT64 IPv6 transition prefixes, allowing unauthorized access to cloud metadata and internal network services.
date: "2026-08-04T20:00:53Z"
lastmod: "2026-08-05T02:01:20Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
tags:
  - ssrf
  - vulnerability
  - cloud-security
  - web-application
  - cve-2026-70479
  - web-vulnerability
  - authorization-bypass
  - cve-2026-70494
vendors:
  - Open WebUI
products:
  - Open WebUI
  - Open WebUI (< 0.11.0)
  - Open WebUI (0.9.6 to 0.10.x)
  - Open WebUI (0.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated users can exploit this to bypass SSRF filters and access internal cloud metadata services.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1568.002
    technique_name: 'Dynamic Resolution: Domain Generation Algorithms'
    evidence: The NAT64 well-known prefix is by design a global prefix carrying an arbitrary IPv4 destination, so an internal target wrapped in it satisfies the check.
    confidence_band: high
cves:
  - id: CVE-2026-70482
references:
  - https://github.com/advisories/GHSA-8x5v-cpv7-8jjp
  - https://github.com/advisories/GHSA-rq84-p6rr-vf89
  - https://github.com/advisories/GHSA-w2rx-84hp-gg95
  - https://github.com/advisories/GHSA-3cg5-48j3-v4gv
  - https://github.com/open-webui/open-webui/pull/27003
rules:
  - title: Detect Potential SSRF Exploitation via NAT64 Encodings
    description: Detects web-retrieval API requests containing NAT64-encoded IPv6 literals, which may indicate an attempt to bypass SSRF filters (CVE-2026-70485).
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1568.002
    data_sources:
      - webserver
  - title: Detect CVE-2026-70494 - Unauthorized Folder Deletion Attempts
    description: Detects DELETE requests to the folders API which may indicate exploitation attempts by collaborators against shared folders
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Open WebUI to v0.11.0
      owner: IT Operations
      due: 48h
      evidence: Fixed in v0.11.0 by commit 1717b493d
  mitigation_plan:
    - priority: immediate
      action: Restrict container egress to cloud metadata and RFC1918 ranges
      owner: IT Operations
      addresses: CVE-2026-70485
      evidence: Vulnerability allows access to cloud metadata including IAM role credentials
updates:
  - at: "2026-08-04T20:00:59Z"
    level: L2
    summary: poc_available; added CVE-2026-70482; open webui version < 0.11.0
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-rq84-p6rr-vf89
  - at: "2026-08-04T20:01:07Z"
    level: L2
    summary: added coverage for Open WebUI (0.9.6 to 0.10.x)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-w2rx-84hp-gg95
  - at: "2026-08-05T02:01:20Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-70494 - Unauthorized Folder Deletion Attempts'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-3cg5-48j3-v4gv
---

Open WebUI (v0.9.0 through v0.10.x) contains an SSRF vulnerability (CVE-2026-70485) stemming from insecure URL validation logic. When processing user-supplied URLs for RAG or web-search features, the application performs connectivity checks to ensure the destination is globally routable. However, this validation uses the `ipaddress.ip_address(ip).is_global` check on the literal IPv6 address, failing to account for embedded IPv4 addresses within NAT64 transition prefixes (specifically `64:ff9b::/96`). 

On cloud environments or Kubernetes clusters configured with NAT64 gateways, an attacker can mask internal IPv4 addresses (such as `169.254.169.254` or `127.0.0.1`) using these prefixes. Because the literal IPv6 representation is technically globally routable, the filter is bypassed. The server subsequently fetches the internal content and returns the raw response body to the attacker via the API. This vulnerability allows low-privilege users to exfiltrate sensitive data, including IAM credentials from cloud instance metadata services or interface with admin endpoints bound to localhost.

## Attack Chain

1. Attacker authenticates to an Open WebUI instance as a standard user.
2. Attacker selects a feature utilizing URL ingestion or web retrieval (e.g., `/api/v1/retrieval/process/web`).
3. Attacker identifies a target internal resource (e.g., Cloud Metadata service at 169.254.169.254).
4. Attacker encodes the target IPv4 address into the NAT64 well-known prefix (`64:ff9b::/96`) to create a literal IPv6 string.
5. Attacker submits the crafted URL (e.g., `http://[64:ff9b::a9fe:a9fe]/latest/meta-data/`) to the vulnerable API endpoint.
6. The application's `validate_url()` and `_ssrf_safe_new_conn()` logic incorrectly flag the NAT64-encoded literal as a valid global IPv6 address.
7. The backend performs an HTTP GET request to the internal destination via the NAT64 gateway.
8. The sensitive response body is returned to the attacker in the `content` field of the API response.

## Impact

Successful exploitation leads to unauthorized read access to internal network services, private APIs, and cloud instance metadata. Attackers can retrieve IAM role credentials, allowing for potential lateral movement from the container to the broader cloud environment. The impact is restricted to deployments utilizing NAT64 gateways, which are standard in modern IPv6-only or dual-stack cloud/Kubernetes network architectures.

## Recommendation

- Upgrade Open WebUI to version 0.11.0 or later to apply the patch for CVE-2026-70485, which correctly unwraps embedded IPv4 addresses before validation.
- Implement network-level egress filtering (Security Groups or Network Policies) to restrict the Open WebUI container from reaching internal cloud metadata IPs (e.g., 169.254.169.254) and private IP ranges.
- Monitor logs for requests to web-retrieval endpoints that contain literal IPv6 addresses starting with `64:ff9b`.
