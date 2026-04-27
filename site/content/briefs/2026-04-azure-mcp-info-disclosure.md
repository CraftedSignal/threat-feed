---
title: Azure MCP Server Missing Authentication Vulnerability (CVE-2026-32211)
slug: 2026-04-azure-mcp-info-disclosure
description: CVE-2026-32211 is a critical vulnerability in Azure MCP Server due to missing authentication for a critical function, allowing an unauthorized attacker to disclose information over the network.
date: "2026-04-03T00:16:04Z"
severities:
  - critical
tags:
  - azure
  - information-disclosure
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-32211
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32211
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32211
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious HTTP Request to Azure MCP Server
    description: Detects suspicious HTTP requests to Azure MCP Server which may indicate CVE-2026-32211 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious POST Request to Azure MCP Server
    description: Detects suspicious POST requests to Azure MCP Server which may indicate CVE-2026-32211 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-32211 is a critical vulnerability affecting Azure MCP Server. The vulnerability stems from a missing authentication check for a critical function. Discovered in early April 2026 and assigned a CVSS v3.1 score of 9.1, this flaw allows an unauthenticated attacker to potentially disclose sensitive information over the network. This could impact the confidentiality of data managed by the MCP server. Defenders need to address this vulnerability to prevent unauthorized access to potentially…
