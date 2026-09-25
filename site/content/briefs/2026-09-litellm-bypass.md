---
title: Tenant Isolation Bypass in BerriAI LiteLLM Semantic Cache
slug: 2026-09-litellm-bypass
description: BerriAI LiteLLM versions prior to 1.101.0-rc.1 are vulnerable to a tenant isolation bypass that allows authenticated users to access other tenants' cached responses through a metadata key mismatch.
date: "2026-09-25T18:54:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:berriai:litellm:*:*:*:*:*:*:*:*
tags:
  - tenant-bypass
  - cve-2026-89032
  - cloud-security
vendors:
  - BerriAI
products:
  - LiteLLM (< 1.101.0-rc.1)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1530
    technique_name: Data from Cloud Storage Object
    evidence: An attacker... can submit semantically similar prompts... to retrieve cached responses containing other tenants' personally identifiable information, financial data, or source code.
    confidence_band: high
cves:
  - id: CVE-2026-89032
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89032
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade BerriAI LiteLLM to version 1.101.0-rc.1 or later
      owner: IT Operations
      addresses: CVE-2026-89032
      evidence: BerriAI LiteLLM before 1.101.0-rc.1 contains a tenant isolation bypass
---

BerriAI LiteLLM versions before 1.101.0-rc.1 contain a tenant isolation bypass vulnerability located within the semantic cache layer. The flaw arises from a mismatch between the functions _get_semantic_cache_tenant_scope() and _get_metadata_variable_name(), which manage the scoping of cache entries. An attacker with a valid virtual key can exploit this logical error by submitting specifically crafted prompts.

By targeting routes such as /v1/responses or /bedrock/*, an authenticated user can retrieve cached responses belonging to other tenants. This unauthorized access can lead to the exposure of sensitive information, including personally identifiable information (PII), financial data, and proprietary source code. Furthermore, the vulnerability enables attackers to manipulate agentic front-ends by injecting malicious payloads into the cache; when retrieved by a different principal, these cached function_call or tool_calls payloads may trigger unintended tool execution under the victim's credentials.

## Impact

The vulnerability results in a loss of data confidentiality and integrity for multi-tenant environments using LiteLLM. Successful exploitation allows unauthorized access to sensitive tenant data and the potential for privilege escalation or remote code execution within agentic workflows through tool call manipulation.

## Recommendation

- Upgrade BerriAI LiteLLM to version 1.101.0-rc.1 or later immediately to resolve the metadata key mismatch in the semantic cache layer.
- Implement strict access controls and audit logging for sensitive endpoints including /v1/responses and routes under /bedrock/*.
- Review cached entries for unexpected or anomalous function_call parameters if suspicion of exploitation arises.
