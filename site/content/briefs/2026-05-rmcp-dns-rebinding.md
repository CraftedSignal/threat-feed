---
brief_id: brief-2026-05-07-rmcp-dns-rebinding
event_id: brief-2026-05-07-rmcp-dns-rebinding
revision: 2
activity_at: "2026-10-29T01:48:47Z"
revision_history:
  - revision: 2
    at: "2026-10-29T01:48:47Z"
    checksum: sha256:5f008aa26dbb2e7beffa7f0701bd00e9a2f8831025b8c1dfaf972951f7b3e4ca
    summary: poc_available; rmcp version < 1.4.0
    changed_fields:
      - affected_products
      - affected_vendors
      - claim_state
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOAOVICDEV-EXPLOIT-CVE-2026-42559&utm_source=rss&utm_medium=rss
title: rmcp Streamable HTTP Server Transport DNS Rebinding Vulnerability
slug: 2026-05-rmcp-dns-rebinding
description: The `rmcp` crate before v1.4.0 is vulnerable to DNS rebinding attacks via the Streamable HTTP server transport due to missing Host header validation, potentially allowing arbitrary code execution on a victim's machine if they visit a malicious website.
date: "2026-05-07T00:00:00Z"
lastmod: "2026-10-29T01:48:07Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOAOVICDEV-EXPLOIT-CVE-2026-42559&utm_source=rss&utm_medium=rss
tags:
  - dns-rebinding
  - vulnerability
  - rmcp
  - http
  - attack
vendors:
  - modelcontextprotocol
  - nubo-db
products:
  - rmcp (< 1.4.0)
  - dynoxide (< 0.9.13)
  - dynoxide-rs (< 0.9.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-42559
    cvss: 8.8
    epss: 0.00269
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-89vp-x53w-74fx
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#security-warning
  - https://github.com/modelcontextprotocol/rust-sdk/pull/764
  - https://github.com/modelcontextprotocol/rust-sdk/issues/822
  - https://github.com/advisories/GHSA-fvh2-gm75-j4j7
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOAOVICDEV-EXPLOIT-CVE-2026-42559&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Suspicious Host Header
    description: Detects HTTP requests with a Host header pointing to a private IP address, which could indicate a DNS rebinding attack.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Access to MCP Server from Non-Local Host
    description: Detects access to an MCP server from a non-loopback address, which may indicate a DNS rebinding attempt if the server is intended to be accessed only locally.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-05-18T17:00:48Z"
    level: L2
    summary: added CVE-2026-42559
    sources:
      - ghsa
  - at: "2026-10-29T01:48:07Z"
    level: L2
    summary: poc_available; rmcp version < 1.4.0
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOAOVICDEV-EXPLOIT-CVE-2026-42559&utm_source=rss&utm_medium=rss
---

The `rmcp` crate, a Rust SDK for the Model Context Protocol (MCP), contains a DNS rebinding vulnerability in its Streamable HTTP server transport. Prior to version 1.4.0, the server did not validate the `Host` header of incoming HTTP requests. This allows a remote attacker to bypass the Same-Origin Policy by exploiting DNS rebinding techniques. By convincing a victim to visit a malicious website, the attacker can make authenticated requests to an MCP server running on the victim's loopback or private network interface. This can lead to the enumeration and invocation of tools exposed by the MCP server, potentially resulting in arbitrary code execution with the victim's privileges. The vulnerability was patched in version 1.4.0 by introducing `Host` header validation with an allowlist.

## Attack Chain

1. Attacker hosts a malicious website with a DNS name configured to perform DNS rebinding.
2. Victim visits the attacker's website, initiating the DNS rebinding attack.
3. The victim's browser resolves the attacker's domain to a loopback IP address (e.g., 127.0.0.1) or a private network IP.
4. The browser sends an HTTP request to the MCP server running on the victim's machine, using the attacker's malicious domain in the `Host` header.
5. The vulnerable `rmcp` server, lacking `Host` header validation prior to v1.4.0, accepts the request as if it originated from a trusted source.
6. The attacker's website sends authenticated requests to the MCP server, leveraging existing credentials or sessions.
7. The attacker enumerates available tools and resources exposed by the MCP server.
8. The attacker invokes tools with malicious intent, potentially leading to file writes, shell execution, API calls, or other actions limited only by the server's exposed functionalities, resulting in arbitrary code execution on the victim's machine.

## Impact

Successful exploitation of this vulnerability allows an attacker to enumerate and invoke any tool exposed by a locally-running `rmcp`-based MCP server, read resources and state accessible via the MCP session, and trigger side effects like file writes or shell execution. Given that MCP servers frequently run with user privileges and expose developer tooling, the practical impact can extend to arbitrary code execution on the victim's machine. This vulnerability affects users running versions of the `rmcp` crate prior to 1.4.0.

## Recommendation

- Upgrade to `rmcp` version 1.4.0 or later to incorporate the fix for CVE-2026-42559.
- If upgrading is not feasible, implement a reverse proxy (e.g., nginx, Caddy) in front of the MCP server and configure it to validate the `Host` header, as outlined in the advisory under "Workarounds for Unpatched Users."
- Deploy the Sigma rule `Detect Suspicious Host Header` to identify potentially malicious requests targeting internal services.
