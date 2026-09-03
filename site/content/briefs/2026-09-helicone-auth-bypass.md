---
title: Authorization Bypass in Helicone VaultManager via Provider Key Retrieval
slug: 2026-09-helicone-auth-bypass
description: An authorization bypass vulnerability in Helicone's VaultManager allows authenticated users to exfiltrate plaintext provider API keys from other organizations due to missing access control checks.
date: "2026-09-03T15:21:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:helicone:vaultmanager:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - credential-access
  - api-security
vendors:
  - Helicone
products:
  - VaultManager
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers with admin or owner privileges in any organization can retrieve decrypted upstream provider credentials for other tenants.
    confidence_band: high
cves:
  - id: CVE-2026-85178
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85178
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit access logs for GET requests to /v1/vault/key/ endpoints.
      owner: SOC
      due: 24h
      evidence: Endpoint documentation in NVD report.
  mitigation_plan:
    - priority: immediate
      action: Rotate all API keys stored within Helicone VaultManager.
      owner: IT Operations
      addresses: CVE-2026-85178
      evidence: Vulnerability allows plaintext key exposure.
---

CVE-2026-85178 is an authorization bypass vulnerability affecting the Helicone VaultManager component. The vulnerability resides within the `getDecryptedProviderKeyById()` function, which is exposed via the `GET /v1/vault/key/{providerKeyId}` endpoint. Security researchers have determined that this function fails to validate whether the requester's organization identifier matches the organization identifier associated with the requested vault key. 

Consequently, any authenticated user possessing admin or owner privileges within any organization using the Helicone platform can bypass intended access controls to retrieve decrypted, plaintext credentials. These credentials include sensitive upstream provider API keys for services such as OpenAI, Anthropic, and Amazon Bedrock. The scope of this issue is significant, as it permits unauthorized cross-tenant credential exfiltration, potentially enabling attackers to consume third-party API quotas or gain unauthorized access to LLM services on behalf of the victim organization. This vulnerability was disclosed on September 3, 2026, and is assigned a CVSS v3.1 base score of 7.7.

## Impact

Successful exploitation allows for the unauthorized retrieval of plaintext API keys belonging to other tenants. This impact includes the potential for financial loss due to unauthorized API usage, exposure of proprietary LLM configurations, and a complete compromise of the credentials protecting downstream AI infrastructure. All organizations utilizing Helicone's vaulting features for API key management are at risk of cross-tenant credential exfiltration if they maintain multiple organizations on the platform.

## Recommendation

Prioritized actions for security teams:
- Audit logs for the `GET /v1/vault/key/` endpoint to identify abnormal patterns of access by user accounts.
- Review all API keys currently managed within the Helicone Vault for evidence of unauthorized usage or rotation requirements.
- Monitor Helicone vendor announcements for security patches addressing CVE-2026-85178 and apply them immediately upon availability.
- Implement monitoring for unusually high volumes of requests to the `vault/key` path emanating from authenticated administrative accounts.
