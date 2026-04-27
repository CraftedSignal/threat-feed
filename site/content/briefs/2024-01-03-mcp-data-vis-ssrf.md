---
title: Server-Side Request Forgery in mcp-data-vis
slug: 2024-01-03-mcp-data-vis-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in AlejandroArciniegas' mcp-data-vis due to improper handling of HTTP requests, potentially allowing remote attackers to make arbitrary requests through the vulnerable server.
date: "2024-01-03T12:00:00Z"
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

A server-side request forgery (SSRF) vulnerability has been identified in AlejandroArciniegas' mcp-data-vis, specifically affecting versions up to commit de5a51525a69822290eaee569a1ab447b490746d. The vulnerability resides within the `axios` function in `src/servers/web-scraper/server.js`, a component responsible for handling HTTP requests. An attacker can exploit this flaw to force the server to make requests to arbitrary internal or external resources, potentially exposing sensitive…
