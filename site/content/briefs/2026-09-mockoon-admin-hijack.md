---
title: Unauthenticated Admin API Exposure in Mockoon
slug: 2026-09-mockoon-admin-hijack
description: Mockoon versions before 9.7.0 expose an unauthenticated, CORS-misconfigured admin API by default, allowing attackers to exfiltrate environment variables, hijack mock responses, and perform cross-origin secret theft.
date: "2026-09-12T00:57:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mockoon:mockoon:*:*:*:*:*:*:*:*
tags:
  - webserver
  - vulnerability
  - cve
vendors:
  - Mockoon
products:
  - commons-server (< 9.7.0)
  - cli (< 9.7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The admin API is enabled by default in every shipped runtime and serves zero authentication of any kind.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: Any unauthenticated caller who can reach the mock server's port can read every MOCKOON_* env var used by the operator as secret material.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: 'The use of wildcard CORS (Access-Control-Allow-Origin: *) permits cross-origin attacks, allowing malicious websites to hijack the mock state and steal secrets.'
    confidence_band: high
cves:
  - id: CVE-2026-59148
    cvss: 8.8
    epss: 0.00262
references:
  - https://github.com/advisories/GHSA-rqx4-3f6q-3x2v
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade @mockoon/cli and @mockoon/commons-server to 9.7.0
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates upgrading to v9.7.0 to address the vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Disable admin API via --disable-admin-api flag on all non-production instances
      owner: IT Operations
      addresses: CVE-2026-59148
      evidence: Source documentation identifies --disable-admin-api as the correct flag for disabling the service.
---

Mockoon, a popular mock server tool, contains a critical security vulnerability in its admin API, which is enabled by default across all runtimes, including `@mockoon/commons-server`, the CLI, and serverless deployments. The admin API, located at `/mockoon-admin/`, lacks any form of authentication or authorization, allowing any unauthenticated user with network access to the server (defaulting to 0.0.0.0:3000) to manipulate the service. Furthermore, the API endpoints explicitly set `Access-Control-Allow-Origin: *`, which permits browser-based attackers to interact with the admin API cross-origin via CSRF. This flaw allows an attacker to steal sensitive `MOCKOON_*` environment variables, inject arbitrary process-level environment variables (e.g., `AWS_SECRET_ACCESS_KEY`), rewrite mock API responses, and harvest sensitive data from transaction logs or Server-Sent Events (SSE). The vulnerability, tracked as CVE-2026-59148, affects all versions prior to 9.7.0.

## Attack Chain

1. Attacker performs network reconnaissance to identify Mockoon instances running on default port 3000 or via local browser-based discovery.
2. Attacker interacts with `/mockoon-admin/env-vars/` endpoints via standard HTTP methods (GET/POST) without authentication to identify and exfiltrate secrets stored as `MOCKOON_*` variables.
3. Attacker uses `POST /mockoon-admin/env-vars/` to inject or overwrite arbitrary process-level environment variables, potentially influencing the host runtime or subsequent SDK operations.
4. Attacker utilizes `PUT /mockoon-admin/environment` to rewrite mock configurations, modifying body contents, status codes, and HTTP headers of downstream mock routes.
5. Attacker leverages wildcard CORS headers to execute cross-origin requests from a malicious webpage, bypassing browser same-origin policies if the developer interacts with the site.
6. Attacker observes live traffic and sensitive client auth headers (e.g., Authorization tokens, Cookies) by querying `/mockoon-admin/logs` or subscribing to the SSE stream at `/mockoon-admin/events`.
7. Final objective is achieved, ranging from credential theft and data exfiltration to complete supply-chain compromise via manipulated mock responses served to integration partners.

## Impact

Successful exploitation allows for the theft of local development secrets, poisoning of production-like staging environments, and the modification of mock responses to inject malicious payloads into downstream testing or CI/CD pipelines. Exposure in CI/CD environments provides a pathway to steal cloud infrastructure credentials or perform man-in-the-middle attacks on internal development tools.

## Recommendation

Prioritized actions for security teams:
- Update all instances of `@mockoon/cli` and `@mockoon/commons-server` to version 9.7.0 or later immediately to patch CVE-2026-59148.
- Audit CI/CD pipelines for exposed Mockoon services; ensure that if the admin API is not strictly required, it is disabled using the `--disable-admin-api` flag.
- Implement network-level restrictions using firewall rules to limit access to the Mockoon admin port (default 3000) to only trusted management subnets.
- Scan for and rotate any environment variables that were hosted in Mockoon environments potentially accessible to unauthorized network traffic, particularly cloud provider keys and JWT secrets.
