---
title: SSRF Vulnerability in mcp-gitlab Enables GitLab Credential Theft
slug: 2026-09-mcp-gitlab-ssrf
description: The mcp-gitlab server is vulnerable to Server-Side Request Forgery (SSRF) when ENABLE_DYNAMIC_API_URL is enabled, allowing attackers to force the server to forward victim GitLab tokens to an arbitrary host.
date: "2026-09-16T01:04:47Z"
lastmod: "2026-09-16T19:07:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:zereight:mcp-gitlab:*:*:*:*:*:*:*:*
tags:
  - dns-rebinding
  - mcp
  - gitlab
  - cve-2026-61568
  - vulnerability
  - rce
  - exfiltration
vendors:
  - zereight
products:
  - mcp-gitlab (>= 0.0.1, <= 2.1.27)
  - mcp-gitlab (< 2.1.30)
  - mcp-gitlab (< 2.1.27)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The server reads the X-GitLab-API-URL HTTP request header and uses it as the base URL for all outbound GitLab API calls made within that request.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Credentials In Files'
    evidence: The server then attaches the victim's Private-Token to every outbound fetch that uses the redirected URL.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1557.001
    technique_name: 'Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay'
    evidence: A malicious web page can use DNS rebinding to route browser requests to a victim's local MCP listener while preserving an attacker-controlled Host and Origin.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The SSE transport mode exposes all MCP tools without any authentication.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1552.003
    technique_name: 'Unsecured Credentials: Credentials in Filesystem'
    evidence: The upload_markdown tool reads arbitrary files from the server's local filesystem.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Any unauthenticated network-reachable attacker can read /proc/self/environ to steal the server's GITLAB_PERSONAL_ACCESS_TOKEN.
    confidence_band: high
cves:
  - id: CVE-2026-61559
    cvss: 9.6
references:
  - https://github.com/advisories/GHSA-2h44-8472-frjj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61559
  - https://github.com/advisories/GHSA-vmp7-252j-cwp7
  - https://github.com/advisories/GHSA-cv3r-c5h8-f4g5
rules:
  - title: Detect CVE-2026-61560 Exploitation - MCP GitLab upload_markdown abuse
    description: Detects unauthorized attempts to trigger the upload_markdown tool via the MCP GitLab API to exfiltrate sensitive files
    platform: sigma
    severity: critical
    tactics:
      - exfiltration
    techniques:
      - T1005
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Disable ENABLE_DYNAMIC_API_URL in all production mcp-gitlab deployments
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends disabling or allowlisting if dynamic URL is enabled.
  enrichment_needed:
    - item: CVE-2026-61559
      owner: CTI
      reason: Monitor for exploit code availability.
  mitigation_plan:
    - priority: immediate
      action: Implement allowlist validation for X-GitLab-API-URL header
      owner: Detection Engineering
      addresses: CVE-2026-61559
      evidence: Remediation section of GHSA-2h44-8472-frjj
updates:
  - at: "2026-09-16T01:04:58Z"
    level: L2
    summary: added coverage for mcp-gitlab (< 2.1.30)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-vmp7-252j-cwp7
  - at: "2026-09-16T19:07:21Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-61560 Exploitation - MCP GitLab upload_markdown abuse'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-cv3r-c5h8-f4g5
---

The npm package @zereight/mcp-gitlab contains a critical SSRF vulnerability (CVE-2026-61559) in all versions through commit 74a8c83. When the configuration variable `ENABLE_DYNAMIC_API_URL` is set to `true`, the application blindly trusts the `X-GitLab-API-URL` HTTP header provided by a requester. The server validates that the header is a well-formed URL but fails to perform any allowlist check or hostname restriction against the destination. 

As a result, an attacker can supply an arbitrary URL via this header. The server subsequently uses this URL for downstream GitLab API calls, attaching the victim's `Private-Token` header to the request before sending it to the attacker-controlled server. This flaw allows attackers to steal credentials and gain full authenticated access to the victim's GitLab account, including CI/CD variables, source code, and project management data. The vulnerability is reachable in multi-user deployment scenarios where `REMOTE_AUTHORIZATION=true` is enabled.

## Attack Chain

1. The target is running `mcp-gitlab` with `ENABLE_DYNAMIC_API_URL=true` and `REMOTE_AUTHORIZATION=true`.
2. The attacker initializes a listener on an external server capable of capturing HTTP headers.
3. The attacker crafts a malicious request to the MCP server's tool execution endpoint.
4. The attacker injects the `X-GitLab-API-URL` header pointing to their listener URL.
5. The MCP server process parses the malicious header and updates the API base URL for the current session.
6. The server initiates a legitimate GitLab API call (e.g., to list issues) using the attacker-supplied URL.
7. The server attaches the victim's `Private-Token` to the request, facilitating the SSRF-based exfiltration.
8. The attacker receives the victim's token via their listener and proceeds to exfiltrate or manipulate GitLab resources.

## Impact

Successful exploitation results in full account compromise at the victim's permission level. Attackers can gain unauthorized access to all repositories, issues, and merge requests, as well as read and modify CI/CD pipelines, secrets, and environment variables. This represents a complete breach of the GitLab security domain for the affected user.

## Recommendation

1. If using `mcp-gitlab` in a multi-user environment, disable `ENABLE_DYNAMIC_API_URL` immediately until a patched version is available.
2. Implement an allowlist for the `X-GitLab-API-URL` header by verifying the hostname against a hardcoded list of trusted GitLab instances before the request is processed.
3. Search web access logs for any incoming requests containing the `X-GitLab-API-URL` header to identify potential exploitation attempts.
4. Rotate all GitLab Personal Access Tokens and CI/CD job tokens for users who interacted with an affected instance of the MCP server.
