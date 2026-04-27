---
title: Azure Databricks SSRF Vulnerability (CVE-2026-33107) Allows Privilege Escalation
slug: 2026-04-azure-databricks-ssrf
description: A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-33107, exists in Azure Databricks, allowing an unauthorized attacker to elevate privileges over a network.
date: "2026-04-03T00:16:05Z"
severities:
  - critical
tags:
  - ssrf
  - azure
  - databricks
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-33107
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33107
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33107
rules:
  - title: Detect Suspicious Databricks Outbound Connections
    description: Detects unusual outbound connections from Azure Databricks that may indicate SSRF attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - azure
  - title: Detect Databricks SSRF via Web Request to Internal IP
    description: Detects attempts to access internal IPs via web requests from Databricks.
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

CVE-2026-33107 describes a critical server-side request forgery (SSRF) vulnerability affecting Azure Databricks. This vulnerability allows an unauthenticated attacker to potentially elevate their privileges within the network. Successful exploitation could allow an attacker to access sensitive data, modify configurations, or potentially gain complete control over the Databricks environment. The vulnerability was published on April 2nd, 2026. Due to the nature of SSRF, this vulnerability could…
