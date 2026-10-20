---
brief_id: brief-2026-10-20-kroxylicious-ssrf
event_id: brief-2026-10-20-kroxylicious-ssrf
revision: 1
activity_at: "2026-10-20T14:17:17Z"
title: Kroxylicious Azure Key Vault KMS provider SSRF (CVE-2026-105941)
slug: 2026-10-kroxylicious-ssrf
description: The Kroxylicious Azure Key Vault KMS provider fails to validate vaultName parameters during EDEK wire-deserialization, enabling SSRF attacks to exfiltrate Azure bearer tokens.
date: "2026-10-20T14:17:17Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:kroxylicious:azure_key_vault_kms_provider:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - cloud-security
  - cloud
vendors:
  - Kroxylicious
products:
  - Azure Key Vault KMS provider
cves:
  - id: CVE-2026-105941
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105941
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Patch Kroxylicious Azure Key Vault KMS provider to the version containing the fix for CVE-2026-105941
      owner: IT Operations
      due: 24h
      evidence: NVD advisory regarding CVE-2026-105941
  hunt_leads:
    - lead: Outbound network connections from proxy servers to non-Azure infrastructure
      technique_id: T1190
      data_needed:
        - Network connection logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: SSRF allows exfiltration of bearer tokens to attacker-controlled hosts
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the patched version of the KMS provider
      owner: IT Operations
      addresses: CVE-2026-105941
      evidence: NVD vulnerability report
---

CVE-2026-105941 describes a critical security vulnerability within the Azure Key Vault KMS provider for Kroxylicious. The issue arises from a failure to perform adequate format validation on the `vaultName` field when handling wire-deserialized Encrypted Data Encryption Key (EDEK) bytes. By providing a crafted `vaultName` during the deserialization process, an unauthenticated attacker can force the application to perform a Server-Side Request Forgery (SSRF) request.

This request is directed toward an attacker-controlled endpoint, effectively exfiltrating the Azure bearer token assigned to the proxy service. Once obtained, the attacker can replay this bearer token against the legitimate Azure Key Vault service. This compromise allows the attacker to bypass the record-encryption trust model, potentially leading to unauthorized access to sensitive data encrypted by the proxy. Given the reliance of the proxy on this token for cryptographic operations, the impact on the confidentiality of the processed data is significant.

## Impact

The vulnerability allows for the exfiltration of sensitive Azure identity tokens used by the Kroxylicious proxy. Successful exploitation results in the compromise of the record-encryption trust model, potentially enabling unauthorized decryption of data handled by the proxy. This impacts any environment using the Kroxylicious Azure Key Vault KMS provider, potentially affecting all organizations managing Kafka record encryption via this service.

## Recommendation

* Monitor network traffic originating from the Kroxylicious service host for unauthorized egress connections to unknown or unexpected external hosts, particularly those attempting to communicate with Azure Identity endpoints.
* Identify and update all instances of the Kroxylicious Azure Key Vault KMS provider to the vendor-patched version immediately to remediate CVE-2026-105941.
* Review Azure Identity logs for signs of anomalous token usage or logins originating from unexpected IP addresses that correlate with potential replayed bearer tokens.
