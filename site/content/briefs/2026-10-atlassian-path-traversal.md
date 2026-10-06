---
title: Critical Path Traversal in Atlassian Data Center Products (CVE-2026-21589)
slug: 2026-10-atlassian-path-traversal
description: An unauthenticated arbitrary file read vulnerability (CVE-2026-21589) in multiple Atlassian Data Center products allows attackers to access sensitive configuration files via a path traversal flaw in the webresource router.
date: "2026-10-06T20:29:05Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - vulnerability
  - web-application
  - path-traversal
vendors:
  - Atlassian
products:
  - Bitbucket Data Center (< 9.4.26, 10.2.8, 10.5.1)
  - Confluence Data Center (< 9.2.26, 10.2.19)
  - Jira Software Data Center (< 9.12.40, 10.3.26, 11.3.12)
  - Jira Service Management Data Center (< 5.12.40, 10.3.26, 11.3.12)
  - Bamboo Data Center (< 10.2.24, 12.1.12)
  - Crowd Data Center (< 6.3.7, 7.0.3, 7.1.7, 7.2.4)
  - Crucible (< 4.9.15)
  - Fisheye (< 4.9.15)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows an unauthenticated attacker to read arbitrary files inside the web application root via the /download/* webresource router.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592.002
    technique_name: 'Gather Victim Org Information: Software'
    evidence: The exploit tools perform product and version detection via public REST endpoints.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The attacker can read arbitrary files including configuration files containing JDBC URLs, passwords, and tokens.
    confidence_band: high
cves:
  - id: CVE-2026-21589
references:
  - https://sploitus.com/exploit?id=BA57A53E-4324-56E4-B89E-4FA516E10711
rules:
  - title: Detect CVE-2026-21589 Exploitation - Path Traversal in Webresource Router
    description: Detects exploitation attempts of CVE-2026-21589 by monitoring for double-encoded path traversal sequences targeting the Atlassian webresource router.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch all Atlassian products to the specified safe versions.
      owner: IT Operations
      due: 24h
      evidence: Source provides list of fixed versions for all affected products.
    - action: Block '%3a%3a' and '::' patterns in WAF.
      owner: SOC
      due: 8h
      evidence: Atlassian-recommended mitigation for unpatched instances.
  hunt_leads:
    - lead: Search for HTTP GET requests containing '..%3a%3a' or '..::' targeting the /download/resources/ endpoint.
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit payload format documentation.
  mitigation_plan:
    - priority: immediate
      action: Deploy Tomcat RewriteValve or urlrewrite.xml configuration changes.
      owner: IT Operations
      addresses: CVE-2026-21589
      evidence: Atlassian security advisory recommendation.
---

CVE-2026-21589 is a critical vulnerability affecting a wide range of self-hosted Atlassian Data Center products, including Bitbucket, Confluence, Jira, Bamboo, Crowd, Crucible, and Fisheye. The vulnerability arises from improper input validation within the `/download/*` webresource router. Specifically, the router performs a double URL-decode and utilizes an unescaping mechanism that converts `::` sequences into `/` characters. This behavior bypasses Tomcat's URI normalization, allowing unauthenticated attackers to perform path traversal and read arbitrary files relative to the web application root.

By targeting the `WEB-INF/` directory, attackers can extract sensitive files such as `web.xml`, `urlrewrite.xml`, and other configuration artifacts that may contain JDBC URLs, API tokens, and private keys. While directory listing is not possible, the predictability of Atlassian application file structures makes this vulnerability highly actionable. Active scanning and proof-of-concept exploits have been observed in the wild shortly after disclosure by watchTowr Labs.

## Attack Chain

1. Attacker sends a specially crafted GET request to the `/download/resources/` endpoint.
2. The path includes a double URL-encoded traversal sequence (e.g., `..%3a%3a`) designed to survive initial Tomcat normalization.
3. The webresource router performs a secondary URL-decode on the URI.
4. The router's `unescapeSlashes` function converts the `::` sequence into a `/` path separator.
5. The application constructs a final path, resulting in a traversal sequence like `../../WEB-INF/web.xml`.
6. The `ServletContext.getResourceAsStream` function resolves the path relative to the application root without further security gating.
7. The application returns the contents of the requested sensitive configuration file in the HTTP response body.
8. Attacker harvests credentials or application metadata from the returned file for subsequent lateral movement.

## Impact

The vulnerability allows unauthenticated information disclosure of highly sensitive configuration data. Successful exploitation provides attackers with the necessary building blocks - such as database credentials and API keys - to compromise the underlying server infrastructure, escalate privileges, or facilitate lateral movement within the network. Multiple self-hosted product lines are affected, and active exploitation has been confirmed following the release of public exploit tooling.

## Recommendation

Prioritized actions for detection and mitigation:

- Upgrade all affected Atlassian Data Center and Server products to the fixed versions specified in the Atlassian September 2026 security advisory immediately.
- Implement a WAF or reverse-proxy rule to block all incoming requests containing `%3a%3a` or `::` character sequences in the URL path.
- Deploy the specific Tomcat RewriteValve or `urlrewrite.xml` mitigation rules provided by Atlassian for instances where immediate patching is not feasible.
- Audit web server access logs for anomalous GET requests targeting the `/download/resources/` endpoint with traversal patterns containing `..%3a%3a` or `..::`.
