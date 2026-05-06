---
title: AxonFlow Platform Multi-Tenant Isolation and Access Control Vulnerabilities
slug: 2026-05-axonflow-multitenant-vulns
description: Multiple vulnerabilities in AxonFlow platform versions prior to 7.5.0, including multi-tenant isolation issues and SQL injection, could lead to unauthorized access, information disclosure, denial of service, and other security impacts; AxonFlow v7.5.0 resolves these issues.
date: "2026-05-07T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - multi-tenancy
  - access-control
  - SQL injection
  - denial of service
  - vulnerability
vendors:
  - AxonFlow
  - GitHub
products:
  - axonflow platform
  - try.getaxonflow.com
  - github.com/getaxonflow/axonflow
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-9h64-2846-7x7f
  - https://github.com/getaxonflow/axonflow/blob/main/CHANGELOG.md
  - https://github.com/getaxonflow/axonflow/releases/tag/v7.5.0
rules:
  - title: Detect Unusually Large Request Body
    description: Detects unusually large request bodies, which may indicate a denial-of-service attack attempting to exhaust server memory (CWE-770).
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect Potential SQL Injection Attempts (try.getaxonflow.com)
    description: Detects potential SQL injection attempts based on common SQL injection syntax in requests to try.getaxonflow.com (CWE-89).
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

A consolidated advisory addresses eight independently-filed bug fixes in AxonFlow platform versions before 7.5.0, resolving multi-tenant isolation, access-control, and policy-enforcement defects. Exploitation of these vulnerabilities could allow attackers to bypass authentication, access sensitive data across tenants, or cause a denial of service. The vulnerabilities include MAP execution multi-tenant isolation (CWE-863), cross-tenant audit-log leaks (CWE-200, CWE-863), license-validation bypass (CWE-862), tenant-scope fail-open (CWE-862), internal-service auth fallback bypass (CWE-863), login timing/org-existence disclosure (CWE-208), portal DoS via unbounded request body (CWE-770), and SQL-injection on the Community SaaS hosted endpoint (CWE-89). The vulnerabilities were identified during an internal security review by AxonFlow in April 2026. The primary remediation is to upgrade to AxonFlow platform version 7.5.0 or later.

## Attack Chain

1.  **Initial Access:** An attacker exploits the license-validation bypass on the `/onboard-customer` endpoint to gain unauthenticated access to the onboarding flow.
2.  **Privilege Escalation:** The attacker leverages the MAP execution multi-tenant isolation vulnerability by providing a malicious `org_id` in the request body to override the authenticated organization ID.
3.  **Defense Evasion:** The attacker bypasses the `apiAuthMiddleware` using the internal-service auth fallback in Evaluation/Enterprise builds, gaining unauthorized access to internal services.
4.  **Information Disclosure:** The attacker exploits the cross-tenant audit-log leak via the `/api/v1/evidence/*` and `/api/v1/decisions/*/explain` handlers to access sensitive audit logs from other tenants.
5.  **Discovery:** The attacker enumerates valid organizations by observing the different timing and response bodies returned by the login handler for invalid organization versus invalid password attempts.
6.  **Denial of Service:** The attacker sends an unbounded request body to the portal, exhausting server memory and causing a denial-of-service condition.
7.  **SQL Injection (Community SaaS):** An attacker crafts SQL-injection-shaped requests to the Community SaaS hosted endpoint (`try.getaxonflow.com`), bypassing governance and potentially influencing the LLM with malicious queries.
8.  **Impact:** Successful exploitation allows unauthorized access to tenant data, policy manipulation, denial-of-service, and potential control over the LLM in the Community SaaS environment.

## Impact

The vulnerabilities collectively pose a significant risk to AxonFlow platform users, particularly those in multi-tenant environments. Successful exploitation of these vulnerabilities could lead to unauthorized access to sensitive data, policy manipulation, denial of service, and in the case of the Community SaaS platform, SQL injection leading to potential LLM compromise. The audit-log leaks could expose confidential business operations. The portal DoS could disrupt service availability, impacting critical business processes. The SQL-injection vulnerability on try.getaxonflow.com allows attackers to inject malicious queries. Upgrading to version 7.5.0 or later is the primary mitigation step.

## Recommendation

*   Upgrade to AxonFlow platform version 7.5.0 or later to remediate all identified vulnerabilities.
*   For those unable to upgrade immediately, ensure the agent middleware sets `X-Org-ID` / `X-Tenant-ID` from authenticated identity at the ingress, never accepting body-supplied identity (mitigates Items 1–5).
*   For Community SaaS users unable to upgrade immediately, set `SQLI_ACTION=block` explicitly via the agent task definition to mitigate the SQL-injection vulnerability (Item 8).
*   Monitor web server logs for abnormally large request bodies targeting the AxonFlow portal, indicative of potential DoS attempts (CWE-770).
*   Deploy a web application firewall (WAF) to filter SQL-injection attempts targeting the `try.getaxonflow.com` endpoint.
