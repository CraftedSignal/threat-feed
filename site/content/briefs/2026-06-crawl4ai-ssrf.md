---
title: Crawl4AI Unauthenticated SSRF in Docker API `crawl/stream` Endpoint
slug: 2026-06-crawl4ai-ssrf
description: A remote, unauthenticated attacker can exploit an unpatched Server-Side Request Forgery (SSRF) vulnerability in Crawl4AI Docker API versions up to 0.8.9, specifically targeting the `/crawl/stream` endpoint, to read internal network services and cloud-metadata endpoints, potentially exposing sensitive information like IAM credentials.
date: "2026-06-18T17:41:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - web-application
  - docker
  - unauthenticated
  - api-exploitation
vendors:
  - Crawl4AI
products:
  - crawl4ai (<= 0.8.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1590
    technique_name: Gather Victim Network Information
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-wm69-2pc3-rmmf
rules:
  - title: Detect Crawl4AI SSRF to Internal IPs via /crawl/stream
    description: Detects unauthenticated POST requests to the Crawl4AI /crawl/stream endpoint containing internal IP addresses in the URL query, indicating an SSRF attempt to access internal services or cloud metadata.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
      - T1590
    data_sources:
      - webserver
  - title: Detect Crawl4AI SSRF to Internal IPs via /crawl with stream=true
    description: Detects unauthenticated POST requests to the Crawl4AI /crawl endpoint with 'crawler_config.stream=true' and an internal IP address in the URL query, indicating an SSRF attempt.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
      - T1590
    data_sources:
      - webserver
rules_count: 2
---

A remote, unauthenticated attacker can exploit an unpatched Server-Side Request Forgery (SSRF) vulnerability in the Crawl4AI Docker API server, specifically targeting versions up to 0.8.9. The vulnerability exists because the `handle_stream_crawl_request` function, used by `POST /crawl/stream` and `POST /crawl` with `crawler_config.stream=true`, fails to validate the destination of provided seed URLs. This oversight allows attackers to supply URLs pointing to internal networks, private IP addresses, or cloud-metadata endpoints (e.g., `http://169.254.169.254/`). The server then fetches the content from these internal resources and streams the response directly back to the attacker, potentially leading to unauthorized access to sensitive information like cloud IAM credentials or details about internal services. This critical flaw highlights a gap in the API's security checks, which was previously intended to prevent such attacks on non-streaming paths but was overlooked for streaming functionalities. The Docker API is often unauthenticated by default, increasing the attack surface.

## Attack Chain

1.  Attacker identifies an internet-facing Crawl4AI Docker API server (version <= 0.8.9).
2.  Attacker crafts an unauthenticated `POST` request targeting the `/crawl/stream` endpoint, or the `/crawl` endpoint with `crawler_config.stream=true`.
3.  Within the request body, the attacker includes a malicious seed URL pointing to an internal, private, or link-local address, such as `http://169.254.169.254/latest/meta-data/`.
4.  The Crawl4AI server's `handle_stream_crawl_request` function processes the request without applying the necessary `validate_url_destination` check.
5.  The server initiates an outbound connection to the specified internal URL, fetching the content of the internal resource (e.g., cloud instance metadata).
6.  The fetched response body (e.g., AWS IAM temporary credentials) is then streamed back by the Crawl4AI server to the unauthenticated attacker's client.
7.  The attacker receives and extracts sensitive internal information or credentials from the streamed response.
8.  Attacker potentially uses the obtained credentials to escalate privileges or access other internal cloud resources.

## Impact

This unauthenticated Server-Side Request Forgery (SSRF) allows remote attackers to read arbitrary internal services and cloud-metadata endpoints. This can expose highly sensitive information such as cloud IAM temporary credentials (e.g., from `http://169.254.169.254/latest/meta-data/iam/security-credentials/`), internal network topology, or other confidential data hosted on inaccessible internal systems. The vulnerability is considered high severity due to its unauthenticated nature and direct access to internal resources, which is similar in class and impact to previously identified SSRF flaws in the project. Successful exploitation could lead to privilege escalation, data exfiltration, or broader compromise of cloud environments.

## Recommendation

*   Upgrade Crawl4AI instances to version 0.9.0 or later to patch the SSRF vulnerability.
*   Enable authentication on the Crawl4AI Docker API and restrict access to authorized users/systems only.
*   Implement egress filtering or network segmentation to restrict outbound network access from Crawl4AI containers, preventing connections to internal or metadata service IP ranges like `169.254.169.254`.
*   Deploy the provided Sigma rules to your SIEM to detect attempts at exploiting the `/crawl/stream` or `/crawl` (with `crawler_config.stream=true`) endpoints with internal IP addresses.
*   Ensure webserver access logs are enabled and ingested into your SIEM for the Crawl4AI application to allow detection of malicious `POST` requests targeting `/crawl/stream` or `/crawl`.
