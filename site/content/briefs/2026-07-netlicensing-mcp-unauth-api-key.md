---
title: Unauthenticated API Key Use in NetLicensing-MCP HTTP Mode
slug: 2026-07-netlicensing-mcp-unauth-api-key
description: An unauthenticated vulnerability exists in netlicensing-mcp (version 0.1.5 and earlier) when operating in HTTP transport mode, where the ApiKeyMiddleware fails to enforce authentication for requests lacking a client API key, causing the application to fall back to the server's NETLICENSING_API_KEY environment variable for upstream calls, allowing an unauthenticated network attacker to invoke any MCP tool under the server operator's identity and account quota.
date: "2026-07-14T20:49:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - missing-authentication
  - api-security
  - supply-chain
  - http
vendors:
  - NetLicensing
products:
  - netlicensing-mcp (0.1.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated network attacker can therefore invoke any MCP tool — including product listing, license creation/modification, and destructive delete operations — entirely under the operator's identity and account quota.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The downstream client module (`src/netlicensing_mcp/client.py`) uses a Python `ContextVar` named `api_key_ctx` with a default of `os.getenv("NETLICENSING_API_KEY", "")` (line 30). Because the middleware never sets this context variable for unauthenticated requests, `api_key_ctx.get()` returns the server-level environment variable. The client then encodes this value into an HTTP Basic Authorization header (`lines 62–70`) and transmits it to the upstream NetLicensing REST API on every request (`lines 105, 109`).
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The downstream HTTP client then falls back to the server operator's `NETLICENSING_API_KEY` environment variable (`client.py:30`) and uses it to authenticate every upstream call to the NetLicensing REST API.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Data Destruction
    evidence: Bulk deletion of products, licenses, or licensees, destroying the operator's licensing configuration.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: Bulk deletion of products, licenses, or licensees, destroying the operator's licensing configuration.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-x9vc-9ffq-p3gj
---

NetLicensing-MCP, an open-source tool designed for managing NetLicensing accounts, contains a critical vulnerability (CVSS 8.1) when deployed in HTTP transport mode, specifically affecting version 0.1.5 and earlier. The `ApiKeyMiddleware` fails to properly enforce authentication for incoming HTTP requests that lack a client API key. Instead of rejecting such unauthenticated requests, the application inadvertently proceeds, falling back to using the server operator's `NETLICENSING_API_KEY` environment variable for all subsequent upstream calls to the NetLicensing REST API. This flaw allows any unauthenticated network attacker to invoke any MCP tool functions, including product listing, license creation, modification, and destructive delete operations, entirely under the server operator's identity and account quota. Identified as a Missing Authentication for Critical Function (CWE-306), this vulnerability primarily impacts organizations running `netlicensing-mcp` on network-reachable interfaces with the `NETLICENSING_API_KEY` configured as per official documentation.

## Attack Chain

1. An unauthenticated network attacker sends an HTTP request to the `netlicensing-mcp` `/mcp` endpoint, intentionally omitting any `x-netlicensing-api-key` header or `apikey` query parameter.
2. The `ApiKeyMiddleware` in `src/netlicensing_mcp/server.py` attempts to extract an API key from the incoming request.
3. Because no client key is provided by the attacker, the middleware fails to find one and unconditionally forwards the unauthenticated request to the next handler (`call_next(request)` at `server.py:1427`).
4. The downstream MCP client module (`src/netlicensing_mcp/client.py`) is invoked and attempts to obtain an API key for making upstream calls to the NetLicensing REST API.
5. The `api_key_ctx` ContextVar in `client.py` defaults to `os.getenv("NETLICENSING_API_KEY", "")` (at `client.py:30`), retrieving the server operator's confidential API key from the environment.
6. The MCP client proceeds to construct an `Authorization: Basic` header using the server operator's retrieved API key (`client.py:62 - 70`).
7. The MCP client then makes an upstream HTTP request to the NetLicensing REST API (e.g., to `/core/v2/rest/product`) using the operator's credentials (`client.py:105, 109`).
8. The upstream NetLicensing API processes the request as if it originated from the legitimate server operator, granting the attacker full control over the operator's account via the MCP tools.

## Impact

This vulnerability, categorized as Missing Authentication for Critical Function (CWE-306), allows any network-reachable attacker to invoke the full set of MCP tools without authentication. Attackers can execute read, create, update, and delete operations, with their requests transparently executed under the server operator's NetLicensing account. This leads to:

- **Confidentiality**: Unauthorized enumeration of all products, licenses, licensees, and transactions linked to the operator's account.
- **Integrity**: Unauthorized creation of new licenses or licensees, modification of existing license parameters, and forging of token-based validations.
- **Availability**: Potential for bulk deletion of products, licenses, or licensees, which could severely disrupt or destroy the operator's entire licensing configuration.

The vulnerability specifically impacts operators who deploy `netlicensing-mcp` in HTTP transport mode (`python3 -m netlicensing_mcp.server http`) with the `NETLICENSING_API_KEY` configured as a server-side environment variable and expose the service on a network-reachable interface. This deployment pattern is officially documented in the project README for remote and cloud deployments.

## Recommendation

* Upgrade `netlicensing-mcp` to a patched version (newer than 0.1.5) immediately to address the vulnerability in `src/netlicensing_mcp/server.py`.
* Apply the suggested patch from the advisory to `src/netlicensing_mcp/server.py` to correctly reject unauthenticated requests to the `/mcp` endpoint if an upgrade is not immediately feasible.
* Review server configurations to ensure that the `netlicensing-mcp` service, particularly the vulnerable `/mcp` endpoint (IOC: `/mcp`), is not exposed on network-reachable interfaces when operating in HTTP mode with the `NETLICENSING_API_KEY` environment variable set.
* Implement web application firewall (WAF) rules to block HTTP requests directed at the `/mcp` endpoint (IOC: `/mcp`) that do not contain an `x-netlicensing-api-key` header or `apikey` query parameter, effectively mimicking the behavior of a patched `ApiKeyMiddleware`.
* Monitor web server access logs for HTTP requests targeting the `/mcp` endpoint (IOC: `/mcp`) that lack explicit API key authentication, as this may indicate attempted exploitation.
