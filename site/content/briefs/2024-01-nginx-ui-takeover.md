---
brief_id: brief-2024-01-09-nginx-ui-takeover
event_id: brief-2024-01-09-nginx-ui-takeover
revision: 2
activity_at: "2026-11-20T03:11:01Z"
revision_history:
  - revision: 2
    at: "2026-11-20T03:11:01Z"
    checksum: sha256:dcd687d180bf16f417bc17aed1678703d0a1b33bfa9ded386d1b26a0af489d65
    summary: exploited:true; KEV CVE-2026-20133; KEV CVE-2026-32202; KEV CVE-2026-34621; KEV CVE-2024-1708; KEV CVE-2025-2749
    changed_fields:
      - affected_os
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - exploitation_evidence
      - has_poc
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Unauthenticated Remote Takeover of Nginx-UI via MCP Endpoint
slug: 2024-01-nginx-ui-takeover
description: Nginx-UI is vulnerable to unauthenticated remote takeover due to a missing authentication check on the `/mcp_message` endpoint, allowing attackers to invoke MCP tools without authentication, leading to arbitrary nginx configuration modification, traffic interception, service disruption, configuration exfiltration, and credential harvesting; the default empty IP whitelist allows access from any network attacker.
date: "2024-01-09T12:00:00Z"
lastmod: "2026-11-20T03:10:25Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-04-13T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:adobe:acrobat:*:*:*:*:classic:*:*:*
  - cpe:2.3:a:adobe:acrobat_dc:*:*:*:*:continuous:*:*:*
  - cpe:2.3:a:adobe:acrobat_reader_dc:*:*:*:*:continuous:*:*:*
  - cpe:2.3:a:cisco:catalyst_sd-wan_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:catalyst_sd-wan_manager:20.12.6:*:*:*:*:*:*:*
  - cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*
  - cpe:2.3:a:kentico:xperience:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
has_poc: true
tags:
  - nginx-ui
  - nginx
  - unauthenticated
  - remote-takeover
  - CVE-2026-33032
vendors:
  - Adobe
  - Apache
  - Cisco
  - ConnectWise
  - cPanel
  - D-Link
  - Fortinet
  - Ivanti
  - JetBrains
  - Kentico
  - Microsoft
  - PaperCut
  - Quest
  - Samsung
  - SimpleHelp
  - Synacor
products:
  - Acrobat Reader
  - ActiveMQ Broker
  - Adobe Acrobat
  - Apache ActiveMQ
  - Catalyst SD-WAN Manager
  - cPanel
  - Defender
  - DIR-823X
  - Endpoint Manager Mobile
  - Excel Viewer
  - Exchange Server
  - FortiClient EMS
  - KACE Systems Management Appliance
  - Kentico Xperience
  - MagicINFO Server
  - Marimo
  - Office
  - Office Compatibility Pack
  - Office Excel
  - PaperCut MF
  - PaperCut NG
  - ScreenConnect
  - SharePoint Server
  - SimpleHelp remote support software
  - TeamCity On-Premises
  - Visual Basic for Applications
  - WHM
  - Windows Server
  - Windows Server Host Process for Windows Tasks
  - Windows Shell
  - WP Squared
  - Zimbra Collaboration Suite (ZCS)
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.003
    technique_name: Web Shell
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2024-1708
    cvss: 8.4
    epss: 0.85271
    kev: true
    kev_status: "true"
  - id: CVE-2025-2749
    cvss: 7.2
    epss: 0.04902
    kev: true
    kev_status: "true"
  - id: CVE-2026-20133
    cvss: 6.5
    epss: 0.01356
    kev: true
    kev_status: "true"
  - id: CVE-2026-32202
    cvss: 4.3
    epss: 0.07193
    kev: true
    kev_status: "true"
  - id: CVE-2026-34621
    cvss: 8.6
    epss: 0.12155
    kev: true
    kev_status: "true"
  - id: CVE-2026-33032
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-h6c2-x2m2-mwhf
  - https://www.recordedfuture.com/blog/april-cve-landscape
iocs:
  - type: url
    value: http://target:9000/mcp_message
ioc_counts:
  url: 1
rules:
  - title: Detect Nginx-UI MCP Message Endpoint Usage
    description: Detects requests to the /mcp_message endpoint in Nginx-UI, which is vulnerable to unauthenticated command execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Nginx-UI Config Modification via MCP Message
    description: Detects requests to the /mcp_message endpoint that include 'nginx_config_add' or 'nginx_config_modify' in the request body.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - impact
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-05-15T14:03:08Z"
    level: L2
    summary: poc_available; added CVE-2024-1708 +4; OS windows server
    sources:
      - recorded-future
  - at: "2026-11-20T03:10:25Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-20133; KEV CVE-2026-32202; KEV CVE-2026-34621; KEV CVE-2024-1708; KEV CVE-2025-2749
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

The nginx-ui MCP (Model Context Protocol) integration exposes two HTTP endpoints: `/mcp` and `/mcp_message`. While `/mcp` requires authentication, the `/mcp_message` endpoint only applies IP whitelisting - and the default IP whitelist is empty, which the middleware treats as "allow all". This vulnerability, affecting nginx-ui versions 1.99 and earlier, allows any network attacker to invoke all MCP tools without authentication via the `/mcp_message` endpoint. This includes restarting nginx, creating/modifying/deleting nginx configuration files, and triggering automatic config reloads. Successful exploitation leads to complete nginx service takeover. This is critical for defenders as it provides an unauthenticated pathway to control a critical piece of infrastructure typically fronting web applications.

## Attack Chain

1. Attacker sends an HTTP POST request to `http://target:9000/mcp_message` with a JSON payload.
2. The request bypasses authentication checks due to the missing `AuthRequired()` middleware on the `/mcp_message` endpoint.
3. The `IPWhiteList()` middleware allows all requests because the default IP whitelist is empty.
4. The request is routed to the `mcp.ServeHTTP()` handler.
5. The attacker invokes the `nginx_config_add` MCP tool to create a malicious nginx configuration file, for example in `/etc/nginx/conf.d/`.
6. The `nginx_config_add` tool writes the malicious configuration file to disk.
7. After the config is written, `nginx_config_add` attempts to reload nginx configuration via `nginx.Control(nginx.Reload)`.
8. The attacker now controls the Nginx webserver and can intercept traffic, redirect users, and exfiltrate data.

## Impact

Successful exploitation of this vulnerability grants an unauthenticated attacker complete control over the nginx service. This allows the attacker to intercept traffic, rewrite server blocks, capture credentials and session tokens, and disrupt service by writing invalid configurations. All existing nginx configurations are readable via `nginx_config_get`, potentially revealing backend topology and authentication headers. This poses a significant risk to organizations relying on nginx-ui to manage their web servers.

## Recommendation

*   Apply the patch suggested in the advisory by adding `middleware.AuthRequired()` to the `/mcp_message` route to prevent unauthenticated access (reference: GitHub advisory).
*   Deploy the Sigma rule "Detect Nginx-UI MCP Message Endpoint Usage" to identify potential exploit attempts in your environment (reference: Sigma rule below).
*   Monitor network connections to port 9000 (default nginx-ui port) for suspicious POST requests to `/mcp_message` (reference: IOC).
*   Consider changing the default IP whitelist behavior to deny-all when unconfigured (reference: GitHub advisory).
