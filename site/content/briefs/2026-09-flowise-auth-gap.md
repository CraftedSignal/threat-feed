---
title: Flowise Cross-Tenant Authorization Vulnerability
slug: 2026-09-flowise-auth-gap
description: Flowise versions before 3.1.4 contain authorization gaps in Enterprise endpoints that allow authenticated users to perform cross-tenant operations including unauthorized workspace deletion and SSO credential access.
date: "2026-09-15T17:42:48Z"
lastmod: "2026-09-15T17:43:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:flowiseai:flowise:*:*:*:*:enterprise:*:*:*
tags:
  - path-traversal
  - arbitrary-file-write
  - rce
  - xss
vendors:
  - Flowise
products:
  - Flowise Enterprise (< 3.1.4)
  - Flowise (< 3.1.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Flowise before 3.1.4 contains a remote code execution vulnerability in the Custom MCP node that allows authenticated attackers to execute arbitrary code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attacker-controlled npm packages to execute code on the Flowise server.
    confidence_band: high
cves:
  - id: CVE-2026-91929
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91929
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91931
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91934
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Flowise Enterprise to 3.1.4
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends version 3.1.4.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 3.1.4
      owner: IT Operations
      addresses: CVE-2026-91929
      evidence: NVD advisory
updates:
  - at: "2026-09-15T17:43:03Z"
    level: L2
    summary: added coverage for Flowise (< 3.1.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-91931
  - at: "2026-09-15T17:43:16Z"
    level: L2
    summary: added coverage for Flowise (< 3.1.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-91934
---

Flowise versions prior to 3.1.4 are affected by critical cross-tenant authorization flaws within their Enterprise endpoint implementations. The vulnerability arises from a failure to validate resource ownership during API operations. An attacker who has legitimate access to an Enterprise instance can exploit these endpoints to interact with resources belonging to other tenants within the same installation.

Successful exploitation allows for a range of unauthorized activities, including the deletion of arbitrary workspaces, unauthorized self-invitation into external organizations, modification of cross-organization roles, and the retrieval of stored Single Sign-On (SSO) secrets. Given the potential for complete control over tenant configuration and the exposure of sensitive authentication material, this vulnerability poses a high risk to organizations utilizing Flowise Enterprise.

## Impact

The vulnerability allows authenticated attackers to compromise the confidentiality, integrity, and availability of multi-tenant Flowise environments. Impact includes the destruction of victim workspace data, potential account takeovers via cross-org role escalation, and the compromise of sensitive SSO configuration secrets, which could lead to further downstream attacks against integrated corporate identity providers.

## Recommendation

* Update all Flowise Enterprise instances to version 3.1.4 or later immediately.
* Review audit logs for anomalous API requests targeting organization management endpoints or role modifications that appear outside of authorized administrative workflows.
* Monitor for unauthorized workspace deletions or suspicious additions of new users to high-privilege organization roles.
* Rotate all SSO secrets and configuration keys stored within Flowise Enterprise if there is suspicion that an unauthenticated or unauthorized actor accessed the system prior to patching.
