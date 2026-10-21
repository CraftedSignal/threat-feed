---
brief_id: brief-2026-10-21-emudhra-ca-compromise
event_id: brief-2026-10-21-emudhra-ca-compromise
revision: 2
activity_at: "2026-10-21T07:57:27Z"
revision_history:
  - revision: 2
    at: "2026-10-21T08:50:04Z"
    checksum: sha256:543d7ba1df98b67542519f76f565599c88ab14089828cc741dc9f4a5d974f3e9
    summary: Consolidated duplicate public page into the detailed intermediate CA brief.
    changed_fields:
      - draft
    maintenance: true
draft: true
title: 'eMudhra: Weak Private Key Generation in Intermediate CA Certificates'
slug: 2026-10-emudhra-ca-compromise
description: eMudhra issued eight P384 intermediate CA certificates with predictably weak private keys, resulting in trivial key recovery due to flawed key generation processes.
date: "2026-10-21T07:57:27Z"
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
  validation_status: Source-confirmed; no technical remediation beyond certificate revocation is applicable.
vendors:
  - eMudhra
products:
  - eMudhra CA Intermediate Certificates (P384)
references:
  - https://seclists.org/oss-sec/2026/q4/276
  - https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit environment for certificates chained to the identified eMudhra P384 intermediate CA.
      owner: IT Operations
      due: 48h
      evidence: Investigation into the impacted keys revealed they originate from a specific batch of 24 intermediates.
  mitigation_plan:
    - priority: immediate
      action: Revoke and replace all certificates issued by the 8 identified compromised eMudhra intermediate keys.
      owner: IT Operations
      addresses: Compromised eMudhra P384 Intermediate Certificates
      evidence: The 8 impacted keys were recovered trivially, necessitating revocation.
---

An audit of eMudhra intermediate certificates has identified that eight P384 intermediate certificates, generated in April 2025, contain weak private keys. The private keys were constrained to integers less than 256, effectively rendering them predictable. These keys were recovered trivially by researchers using simple discrete logarithm algorithms, as the private keys were essentially all-zeroes with only the final byte varied. This failure originated during the key generation process rather than the signing process. The organization has revoked the impacted keys, and audits are now required for other CA root and intermediate certificates to identify similar implementation flaws.

## Impact

The use of weak, predictable private keys allows unauthorized parties to recover the private key of the certificate, enabling the impersonation of the CA or the issuance of fraudulent certificates within the trust chain.

## Recommendation

- Inventory all certificates signed by the affected eMudhra intermediate CA chain.
- Revoke and replace any certificates issued by the compromised intermediates.
- Implement automated auditing for all CA root and intermediate keys to verify the entropy and randomness of private key generation, ensuring they meet cryptographic standards.
- Monitor certificate transparency logs for anomalous or unauthorized certificate issuances linked to eMudhra infrastructure.
