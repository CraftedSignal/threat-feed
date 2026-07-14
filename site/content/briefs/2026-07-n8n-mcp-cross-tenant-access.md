---
title: n8n-mcp Cross-Tenant Workflow Version Access Vulnerability
slug: 2026-07-n8n-mcp-cross-tenant-access
description: A critical cross-tenant access vulnerability exists in n8n-mcp versions up to 2.56.0, specifically in multi-tenant HTTP deployments. An authenticated tenant can read, delete, or destroy workflow version backups belonging to other tenants due to insufficient isolation of locally stored version history. This exposure includes sensitive data such as credential references and authorization headers embedded in node definitions, posing both a confidentiality and integrity/availability risk.
date: "2026-07-14T19:15:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - cross-tenant
  - n8n
vendors:
  - n8n
products:
  - n8n-mcp <= 2.56.0
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: An authenticated tenant could read workflow version snapshots belonging to other tenants.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: and could delete or destroy other tenants' stored backups.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-j6r7-6fhx-77wx
---

A critical cross-tenant access vulnerability, identified as CVE-2026-54052, has been discovered in n8n-mcp versions up to 2.56.0. This flaw specifically affects multi-tenant HTTP deployments of n8n-mcp, a popular workflow automation tool, where a single server manages multiple tenant instances. The vulnerability stems from inadequate isolation of locally stored workflow version history, allowing an authenticated tenant to read, delete, or destroy workflow version backups belonging to other tenants. These backups contain sensitive data, including credential references and authorization headers from node definitions, thereby posing significant confidentiality, integrity, and availability risks to affected organizations. While no specific threat actors have been attributed to exploiting this vulnerability in the wild, the potential for unauthorized access to sensitive tenant data makes it a high-priority concern for defenders.

## Attack Chain

1. **Initial Access**: An attacker obtains valid authentication credentials for a legitimate tenant account within an affected n8n-mcp multi-tenant HTTP deployment.
2. **Authentication**: The attacker successfully authenticates to the n8n-mcp instance using the compromised tenant credentials.
3. **Discovery**: While authenticated, the attacker accesses the workflow version history feature, typically available via the user interface or API endpoints.
4. **Exploitation**: Due to the vulnerability (CVE-2026-54052) stemming from insufficient isolation of locally stored backups, the attacker's request for workflow versions unintentionally exposes or grants access to version backups associated with other tenants.
5. **Collection**: The attacker reads sensitive information, such as credential references and authorization headers, directly from the exposed workflow version snapshots of other tenants.
6. **Impact/Manipulation**: The attacker may then delete or destroy the workflow version backups of other tenants, impacting data integrity and availability.
7. **Exfiltration**: The attacker exfiltrates the collected sensitive data, such as authentication credentials, from the compromised workflow backups for further malicious use.

## Impact

In multi-tenant HTTP deployments where a single n8n-mcp server serves several tenants, the locally stored workflow version history (automatic backups taken before workflow updates) was not isolated per tenant. An authenticated tenant could read workflow version snapshots belonging to other tenants, and could delete or destroy other tenants' stored backups. A stored snapshot includes full node definitions, so the exposed data can contain credential references and authorization headers configured on nodes. This is therefore a confidentiality issue in addition to an integrity/availability one. There is no information available regarding the number of victims or specific sectors targeted, but any organization using affected configurations of n8n-mcp is at risk of sensitive data exposure and denial of service.

## Recommendation

* Upgrade n8n-mcp instances to version `2.56.1` immediately to patch CVE-2026-54052, which isolates stored version history per instance.
* If immediate upgrade to `n8n-mcp` version `2.56.1` is not possible, disable the workflow version tool by setting `DISABLED_TOOLS=n8n_workflow_versions` in the server environment (e.g., Docker `.env`) to close the cross-tenant access path.
* Alternatively, avoid running `n8n-mcp` in multi-tenant mode by serving each tenant from a separate instance with its own database, ensuring no local store is shared between tenants.
* Restrict network access to the `n8n-mcp` HTTP endpoint to trusted operators only.
