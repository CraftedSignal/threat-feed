---
title: PraisonAI Authentication Bypass Vulnerability (CVE-2026-34953)
slug: 2026-04-praisonai-auth-bypass
description: PraisonAI versions prior to 4.5.97 are vulnerable to an authentication bypass (CVE-2026-34953) where OAuthManager.validate_token() incorrectly validates arbitrary tokens, granting attackers unauthorized access to registered tools and agent capabilities.
date: "2026-04-04T12:00:00Z"
severities:
  - critical
tags:
  - cve-2026-34953
  - authentication-bypass
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Applications
cves:
  - id: CVE-2026-34953
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34953
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-98f9-fqg5-hvq5
rules:
  - title: Detect PraisonAI Unauthorized Access Attempt
    description: Detects potential unauthorized access attempts to PraisonAI by monitoring for suspicious HTTP requests with authorization headers targeting the MCP server endpoint, indicating a possible exploitation of CVE-2026-34953.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - webserver
      - linux
  - title: PraisonAI Arbitrary Token Usage
    description: Detects the usage of potentially arbitrary tokens within PraisonAI HTTP requests, indicative of CVE-2026-34953 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, contains a critical authentication bypass vulnerability, identified as CVE-2026-34953, affecting versions prior to 4.5.97. The vulnerability resides in the OAuthManager.validate_token() function. Due to an error in token validation, the function returns True for any token not found in its internal store, which is empty by default. This flaw allows any unauthenticated attacker to send an HTTP request to the MCP server with an arbitrary Bearer token. This…
