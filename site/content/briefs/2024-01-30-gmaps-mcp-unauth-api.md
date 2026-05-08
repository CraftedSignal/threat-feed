---
title: gmaps-mcp Unauthenticated HTTP Transport Allows Unlimited Google Maps API Calls
slug: 2024-01-30-gmaps-mcp-unauth-api
description: The gmaps-mcp package allows unauthenticated access to Google Maps API calls when deployed with a blank MCP_API_KEY, potentially leading to significant financial costs for the operator; it also permits path injection attacks.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - googlemaps
  - unauthenticated-access
  - api-abuse
  - injection
vendors:
  - Google
products:
  - Places API
  - gmaps-mcp
references:
  - https://github.com/advisories/GHSA-52cq-7v8r-62c6
iocs:
  - type: url
    value: http://<server>:8000/mcp/
ioc_counts:
  url: 1
rules:
  - title: Detect gmaps-mcp Place ID Injection Attempt
    description: Detects attempts to inject malicious payloads into the place_id parameter when calling the gmaps-mcp API, potentially leading to path injection and unauthorized access to other Google Maps API endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect gmaps-mcp Unauthenticated API Access Attempt
    description: Detects POST requests to the gmaps-mcp API endpoint without a valid X-API-Key header, indicating a potential attempt to exploit the unauthenticated access vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The `gmaps-mcp` package (version 0.1.2 and earlier) is vulnerable to a critical flaw that allows unauthenticated attackers to make unlimited Google Maps API calls at the operator's expense. This occurs because the HTTP transport in `server.py` does not enforce authentication when the `MCP_API_KEY` environment variable is not set, which is the default configuration. As a result, any attacker who knows the server's URL can invoke the API and generate billed requests. The default configuration, as detailed in the README, instructs operators to expose the server via ngrok, making it accessible over the internet. Additionally, the `place_id` parameter in `client.py` is vulnerable to path injection, enabling attackers to manipulate the Places API endpoint.  A Claude skill file is shipped with the package, creating a potential injection surface.

## Attack Chain

1. Operator deploys `gmaps-mcp` with the default configuration, including a blank `MCP_API_KEY` and exposes the server using ngrok per README instructions.
2. Attacker discovers the ngrok URL through public endpoint scans or targeted probes.
3. Attacker sends a POST request to the `/mcp/` endpoint without an `X-API-Key` header, invoking a Google Maps API tool.
4. The `server.py` code at lines 186-192 bypasses authentication checks because `MCP_API_KEY` is unset.
5. The request is forwarded to the Google Maps API, utilizing the operator's `GOOGLE_MAPS_API_KEY`.
6. The Google Maps API processes the request and returns the result to the attacker.
7. The operator's Google Cloud Platform (GCP) account is charged for the API usage.
8. Attacker repeats the process to exhaust the operator's free credit or generate significant charges.

## Impact

Successful exploitation of this vulnerability can result in significant financial losses for the operator due to unauthorized Google Maps API usage. An attacker can quickly exhaust the $200/month free credit, potentially leading to substantial charges. The Places API pricing is roughly $17 per 1,000 requests, and a sustained 1 request/second flood can exhaust the credit in approximately 3 hours. Furthermore, the path injection vulnerability in the `place_id` parameter allows attackers to manipulate the Places API endpoint, potentially forcing higher-cost API calls.

## Recommendation

*   Implement the suggested fix by adding a startup check in `server.py` or `run.py` that exits if `MCP_API_KEY` is unset when using HTTP transport, preventing unauthenticated access (see `server.py` lines 186-192).
*   Update the `.env.example` file to clearly indicate that setting `MCP_API_KEY` is required for HTTP transport (see `.env.example`).
*   Add a warning to the README file before the ngrok instructions, emphasizing the importance of setting `MCP_API_KEY` to prevent unauthorized API calls (see README).
*   Deploy the Sigma rule `Detect gmaps-mcp Place ID Injection Attempt` to identify potential path injection attacks via the `place_id` parameter.
