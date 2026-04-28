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

PraisonAI, a multi-agent teams system, contains a critical authentication bypass vulnerability, identified as CVE-2026-34953, affecting versions prior to 4.5.97. The vulnerability resides in the OAuthManager.validate_token() function. Due to an error in token validation, the function returns True for any token not found in its internal store, which is empty by default. This flaw allows any unauthenticated attacker to send an HTTP request to the MCP server with an arbitrary Bearer token. This request is then incorrectly treated as authenticated, granting the attacker full access to all registered tools and agent capabilities within the PraisonAI system. This vulnerability was patched in version 4.5.97.

## Attack Chain

1. An attacker identifies a PraisonAI instance running a vulnerable version (prior to 4.5.97).
2. The attacker crafts a malicious HTTP request targeting the MCP server endpoint.
3. The HTTP request includes an arbitrary, attacker-controlled Bearer token in the Authorization header.
4. The OAuthManager.validate_token() function is called to validate the provided token.
5. The validate_token function checks its internal store for the presence of the supplied token; because the internal store is empty by default, the check fails.
6. Due to the vulnerability, instead of rejecting the token, the validate_token function incorrectly returns True, indicating successful authentication.
7. The MCP server processes the request as if it originated from an authenticated user.
8. The attacker gains unauthorized access to all registered tools and agent capabilities, enabling them to perform arbitrary actions within the PraisonAI system.

## Impact

Successful exploitation of CVE-2026-34953 allows unauthenticated attackers to gain complete control over the PraisonAI system. This includes access to sensitive data managed by the agents, the ability to execute arbitrary commands, and the potential to disrupt or compromise the entire multi-agent team's workflow. The impact is critical, as it bypasses all authentication mechanisms, making the system completely exposed to unauthorized access. The number of affected organizations depends on the adoption rate of PraisonAI; however, any organization running a vulnerable version is at significant risk.

## Recommendation

*   Immediately upgrade all PraisonAI instances to version 4.5.97 or later to patch CVE-2026-34953.
*   Deploy the Sigma rule "Detect PraisonAI Unauthorized Access Attempt" to identify potential exploitation attempts targeting the MCP server, by looking for HTTP requests with unusual authorization tokens on the webserver logs.
*   Monitor web server logs for HTTP requests with suspicious Authorization headers targeting the MCP server.
