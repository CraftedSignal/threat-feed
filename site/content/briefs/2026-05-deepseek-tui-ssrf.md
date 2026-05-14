---
title: DeepSeek TUI SSRF Vulnerability via HTTP Redirect Bypass (CVE-2026-45310)
slug: 2026-05-deepseek-tui-ssrf
description: DeepSeek TUI is vulnerable to a Server-Side Request Forgery (SSRF) attack (CVE-2026-45310) because the `fetch_url` tool validates the initial URL against a restricted-IP blocklist but fails to re-validate redirect targets, allowing attackers to exfiltrate sensitive information from cloud-hosted instances by using a redirect to a restricted IP address.
date: "2026-05-14T20:36:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - prompt-injection
  - cloud-metadata
vendors:
  - DeepSeek
products:
  - deepseek-tui (< 0.8.22)
  - deepseek-tui-cli (< 0.8.22)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-96ff-gc8g-wpvg
iocs:
  - type: ip
    value: 169.254.169.254
  - type: url
    value: http://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/&status_code=302
  - type: url
    value: http://httpbin.org/redirect-to?url=http://[collaborator-domain]/ssrf-redirect-bypass&status_code=302
ioc_counts:
  ip: 1
  url: 2
rules:
  - title: Detect SSRF Attempt via Redirect to Restricted IP - Initial Request
    description: Detects CVE-2026-45310 exploitation — initial HTTP request to a public URL that redirects to a restricted IP address.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SSRF Attempt via Redirect to Restricted IP - Connection to Restricted IP
    description: Detects CVE-2026-45310 exploitation — attempts to connect to a restricted IP address after a redirect, indicating potential SSRF bypass.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

DeepSeek TUI is vulnerable to a Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-45310) in versions prior to 0.8.22. The vulnerability exists in the `fetch_url` tool, which is intended to prevent SSRF attacks by validating the initial URL's resolved IP address against a restricted-IP blocklist. However, the HTTP client (`reqwest`) is configured to automatically follow up to 5 redirects without re-validating the redirect target against the same SSRF protections. This allows an attacker to bypass the SSRF protection by using a redirect to a restricted IP address. The attack is triggered via prompt injection, where malicious instructions embedded in files or web content cause the model to call `fetch_url` with an attacker-controlled URL. This allows an attacker to exfiltrate sensitive information from cloud-hosted instances.

## Attack Chain

1. The attacker identifies a DeepSeek TUI instance running a vulnerable version (< 0.8.22).
2. The attacker crafts a prompt containing a malicious URL that exploits the `fetch_url` tool. This prompt could be injected via a file or web content processed by the model.
3. The malicious URL points to a publicly accessible server (e.g., httpbin.org) configured to redirect the request.
4. The redirect target is a restricted IP address, such as a cloud metadata endpoint (e.g., `http://169.254.169.254/latest/meta-data/`).
5. DeepSeek TUI's `fetch_url` tool validates the initial URL, which passes the SSRF filter because it points to a public domain.
6. The `reqwest` HTTP client automatically follows the redirect to the restricted IP address *without* re-validating against the SSRF filter.
7. The `fetch_url` tool connects to the restricted IP address and retrieves sensitive data, such as cloud IAM credentials or instance metadata.
8. The attacker exfiltrates the retrieved data, potentially gaining unauthorized access to cloud resources or sensitive information.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-45310) allows an attacker to bypass intended security controls and access internal services. On cloud-hosted instances (AWS, GCP, Azure), an attacker can exfiltrate cloud IAM credentials, instance metadata, and other sensitive internal service data by redirecting `fetch_url` to `http://169.254.169.254/latest/meta-data/`. This can lead to privilege escalation, data breaches, and unauthorized access to sensitive resources.

## Recommendation

*   Upgrade to DeepSeek TUI version 0.8.22 or later to patch the SSRF vulnerability (CVE-2026-45310).
*   Implement input validation and sanitization to prevent prompt injection attacks that could trigger the `fetch_url` tool with malicious URLs.
*   Monitor network connections originating from DeepSeek TUI instances for connections to internal IP addresses, as indicated in the IOCs.
*   Deploy the Sigma rule to detect attempts to bypass the SSRF filter by redirecting to restricted IP addresses.
