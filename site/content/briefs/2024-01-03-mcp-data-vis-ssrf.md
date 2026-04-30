---
title: Server-Side Request Forgery in mcp-data-vis
slug: 2024-01-03-mcp-data-vis-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in AlejandroArciniegas' mcp-data-vis due to improper handling of HTTP requests, potentially allowing remote attackers to make arbitrary requests through the vulnerable server.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - mcp-data-vis
products:
  - mcp-data-vis
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7146
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7146
rules:
  - title: Detect SSRF Attempts via HTTP Request Parameters
    description: Detects potential SSRF attempts by identifying suspicious URLs in HTTP request parameters targeting the web scraper server.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connections from Web Scraper Server
    description: Detects outbound network connections originating from the web scraper server to unusual ports or internal IP addresses.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability has been identified in AlejandroArciniegas' mcp-data-vis, specifically affecting versions up to commit de5a51525a69822290eaee569a1ab447b490746d. The vulnerability resides within the `axios` function in `src/servers/web-scraper/server.js`, a component responsible for handling HTTP requests. An attacker can exploit this flaw to force the server to make requests to arbitrary internal or external resources, potentially exposing sensitive information or allowing further exploitation of internal systems. The exploit has been publicly disclosed. The lack of versioning details due to the rolling release nature of the project makes it difficult to pinpoint specific affected releases.

## Attack Chain

1.  The attacker identifies an endpoint in `mcp-data-vis` that utilizes the vulnerable `axios` function within `src/servers/web-scraper/server.js`.
2.  The attacker crafts a malicious HTTP request to the identified endpoint, embedding a URL that points to an internal resource (e.g., `http://localhost:6379/`) or an external resource controlled by the attacker in the request parameters.
3.  The `mcp-data-vis` server, upon receiving the malicious request, processes the attacker-controlled URL using the `axios` function without proper validation or sanitization.
4.  The `axios` function then initiates an HTTP request to the attacker-specified URL.
5.  The server receives the response from the targeted resource.
6.  If the target is an internal service, the response might contain sensitive data such as configuration files, internal service status, or API keys.
7.  The `mcp-data-vis` application inadvertently returns the response from the internal/external resource to the attacker.
8. The attacker analyzes the response, extracts sensitive information, or leverages the SSRF vulnerability to further compromise the internal network or external targets.

## Impact

Successful exploitation of this SSRF vulnerability could allow an attacker to read internal files, access internal services, and potentially gain unauthorized access to sensitive information. The lack of response from the project maintainers exacerbates the risk, leaving users vulnerable to attack. The specific impact will vary depending on the internal resources accessible from the `mcp-data-vis` server.

## Recommendation

*   Inspect all HTTP requests handled by `src/servers/web-scraper/server.js` for potentially malicious URLs to detect exploitation attempts (see Sigma rule "Detect SSRF Attempts via HTTP Request Parameters").
*   Deploy the Sigma rules provided to detect potential SSRF attempts targeting the mcp-data-vis application.
*   Monitor network connections originating from the mcp-data-vis server for unusual outbound traffic to internal or external resources (see Sigma rule "Detect Outbound Connections from Web Scraper Server").
