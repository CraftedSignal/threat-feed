---
title: Splunk MCP Server App Cleartext Credential Exposure (CVE-2026-20205)
slug: 2026-04-splunk-mcp-credential-access
description: A user with access to the `_internal` index or the `mcp_tool_admin` capability in Splunk MCP Server app versions below 1.0.3 can view user session and authorization tokens in clear text, leading to potential credential compromise.
date: "2026-04-15T16:16:34Z"
severities:
  - high
tags:
  - splunk
  - credential-access
  - vulnerability
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
cves:
  - id: CVE-2026-20205
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20205
  - https://docs.splunk.com/Documentation/Splunk/latest/Security/Rolesandcapabilities
  - https://help.splunk.com/en/splunk-enterprise/mcp-server-for-splunk-platform/connecting-to-mcp-server-and-admin-settings
rules:
  - title: Splunk Unusual Internal Index Access
    description: Detects unusual access to the _internal index in Splunk, which could indicate potential exploitation of CVE-2026-20205
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
  - title: Splunk MCP Server Admin Capability Usage
    description: Detects the usage of the mcp_tool_admin capability, which could indicate attempts to exploit CVE-2026-20205
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1078
    data_sources:
      - audit
      - splunk
rules_count: 2
---

CVE-2026-20205 affects Splunk MCP Server app versions prior to 1.0.3. The vulnerability allows a low-privileged user with access to the `_internal` index or the `mcp_tool_admin` capability to view sensitive information in cleartext. This information includes user session and authorization tokens. Successful exploitation of this vulnerability requires either local access to the log files where the tokens are stored or administrative access to Splunk's internal indexes. The default configuration…
