---
title: DNS Rebinding Vulnerability in GenieACS MCP Streamable HTTP Transport
slug: 2026-08-genieacs-mcp-dns-rebinding
description: The genieacs-mcp package fails to validate Host and Origin headers on loopback listeners, allowing unauthorized web pages to perform DNS rebinding and invoke administrative GenieACS tools via an unauthenticated MCP interface.
date: "2026-08-25T18:49:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dns-rebinding
  - mcp
  - genieacs
  - remote-code-execution
vendors:
  - GeiserX
products:
  - genieacs-mcp (<= 0.3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1555
    technique_name: Credentials from Web Browsers
    evidence: A malicious web page can use DNS rebinding to route browser requests to a victim's loopback MCP listener while preserving the attacker origin.
    confidence_band: high
cves:
  - id: CVE-2026-55637
references:
  - https://github.com/advisories/GHSA-cmwv-wf9p-p8wx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55637
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Audit environment for active genieacs-mcp instances exposed to loopback or network interfaces.
      owner: IT Operations
      due: 48h
      evidence: Source documentation of default loopback behavior
  mitigation_plan:
    - priority: immediate
      action: Enforce Host/Origin header validation on the MCP gateway.
      owner: IT Operations
      addresses: CVE-2026-55637
      evidence: Remediation section of advisory
---

The `genieacs-mcp` package (versions <= 0.3.1) is vulnerable to a DNS rebinding attack that exploits an unauthenticated Streamable HTTP MCP endpoint. By default, the package binds to `127.0.0.1:8080` and does not enforce authentication, relying on the loopback address as a security boundary. However, browsers can be coerced into sending requests to this loopback address via DNS rebinding from a malicious web page. Because the MCP server fails to validate `Host` and `Origin` headers, it accepts these requests, allowing the attacker to initialize an MCP session and execute sensitive device management tools. This vulnerability effectively permits remote control over the underlying GenieACS NBI interface, enabling actions such as device reboots, firmware updates, and modification of TR-069 configuration parameters.

## Attack Chain

1. The victim visits an attacker-controlled website which initiates a DNS rebinding sequence against an internal or localhost domain.
2. The browser is directed to resolve a malicious domain to `127.0.0.1`, bypassing the Same-Origin Policy.
3. The malicious website sends a crafted HTTP POST request to the local `genieacs-mcp` listener at `127.0.0.1:8080/mcp`.
4. The `genieacs-mcp` server processes the request without verifying the `Host` or `Origin` headers, assuming the loopback traffic is benign.
5. The attacker initializes an MCP session by sending a JSON-RPC `initialize` request, receiving a session ID.
6. The attacker invokes administrative tools such as `get_parameter` or `reboot_device` via `tools/call`.
7. The `genieacs-mcp` backend relays these authenticated tool calls to the target GenieACS NBI, leading to unauthorized device management actions.

## Impact

Successful exploitation allows a remote attacker to act as an authenticated user of the GenieACS MCP interface. This results in unauthorized control over device fleets, including the ability to reboot CPE devices, initiate firmware downloads, and modify TR-069 device parameters. Exposure of these management interfaces presents a significant risk to the integrity and availability of the managed network devices.

## Recommendation

1. Upgrade `genieacs-mcp` to a version that enforces strict `Host` and `Origin` header validation for all HTTP transport requests, including loopback.
2. For current deployments, implement a reverse proxy or WAF layer that rejects requests to the MCP endpoint if the `Host` and `Origin` headers do not match expected local values (e.g., `127.0.0.1:8080` or `localhost:8080`).
3. Require a bearer token for all HTTP transport configurations, even for local loopback interfaces, to mitigate the risk of unauthenticated requests.
4. Consider migrating to the `stdio` transport mode if HTTP-based MCP bridging is not strictly required for the specific integration.
