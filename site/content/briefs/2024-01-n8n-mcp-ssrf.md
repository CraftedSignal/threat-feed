---
title: n8n-mcp Authenticated SSRF Vulnerability
slug: 2024-01-n8n-mcp-ssrf
description: An authenticated server-side request forgery (SSRF) vulnerability affects the webhook trigger tools and the n8n API client in n8n-mcp versions 2.18.7 to before 2.50.2, allowing attackers to make HTTP requests from the n8n-mcp host to internal services and cloud metadata endpoints, potentially leading to credential theft and internal service enumeration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - n8n
  - credential theft
vendors:
  - n8n
products:
  - n8n-mcp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-cmrh-wvq6-wm9r
iocs:
  - type: ip
    value: 169.254.169.254
  - type: ip
    value: 169.254.170.2
  - type: ip
    value: 100.100.100.200
  - type: ip
    value: 192.0.0.192
ioc_counts:
  ip: 4
rules:
  - title: Detect CVE-2026-44694 Exploitation Attempt - Cloud Metadata Request
    description: Detects CVE-2026-44694 exploitation attempt — Outbound HTTP request from n8n-mcp host to known cloud metadata IP addresses indicating potential SSRF exploit
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect CVE-2026-44694 Exploitation Attempt - x-n8n-url Header Usage
    description: Detects CVE-2026-44694 exploitation attempt — Usage of the x-n8n-url header with suspicious URL patterns, potentially indicating SSRF exploit.
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

n8n-mcp versions 2.18.7 before 2.50.2 contain an authenticated Server-Side Request Forgery (SSRF) vulnerability. This flaw resides within the webhook trigger tools, the n8n API client (`N8N_API_URL`), and per-request URLs supplied via the `x-n8n-url` header in multi-tenant HTTP mode. A successful exploit allows a caller with access to the MCP session to trigger HTTP requests originating from the n8n-mcp host, targeting internal services and cloud metadata endpoints. The vulnerability impacts multi-tenant HTTP deployments where tenants share an `AUTH_TOKEN`, single-tenant deployments via indirect prompt injection through tool arguments, and stdio deployments reachable via the same prompt-injection path.

## Attack Chain

1. An attacker gains access to the n8n-mcp instance with valid authentication credentials. This could be through compromised credentials or other vulnerabilities.
2. The attacker crafts a malicious HTTP request targeting a webhook trigger tool or the n8n API client.
3. The attacker injects a URL pointing to an internal service or a cloud metadata endpoint (e.g., `169.254.169.254`) through a tool argument or the `x-n8n-url` header.
4. The n8n-mcp instance, due to the SSRF vulnerability, makes an HTTP request to the attacker-specified internal URL.
5. The internal service responds to the n8n-mcp instance.
6. The n8n-mcp instance forwards the response body back to the attacker, allowing them to enumerate internal services or steal credentials.
7. The attacker extracts sensitive information, such as cloud metadata, API keys, or internal service configuration.
8. The attacker uses the acquired credentials to further compromise the internal network or cloud environment.

## Impact

Successful exploitation of this SSRF vulnerability can lead to significant damage. In multi-tenant environments, a single compromised tenant can exfiltrate temporary IAM / GCP service account / Azure managed-identity credentials. This allows the attacker to gain unauthorized access to cloud resources and potentially compromise other tenants. In single-tenant and stdio deployments, attackers can leverage prompt injection to achieve similar results. The vulnerability enables internal service enumeration and credential theft, potentially leading to lateral movement and data breaches.

## Recommendation

*   Upgrade to `n8n-mcp@2.50.2` or later to patch CVE-2026-44694 and mitigate the SSRF vulnerability.
*   Implement network egress restrictions on the n8n-mcp host to prevent unauthorized access to cloud metadata IPs (`169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `192.0.0.192`) and RFC1918 networks, as described in the workaround section.
*   If immediate upgrade is not possible, disable workflow management tools (`n8n_trigger_webhook_workflow,n8n_create_workflow,n8n_test_workflow`) via `DISABLED_TOOLS` configuration to limit the attack surface.
