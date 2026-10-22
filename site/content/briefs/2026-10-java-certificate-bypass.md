---
brief_id: brief-2026-10-22-java-certificate-bypass
event_id: brief-2026-10-22-java-certificate-bypass
revision: 1
activity_at: "2026-10-22T03:36:55Z"
title: 'Java: Certificate revocation bypass via alternative certificate encoding'
slug: 2026-10-java-certificate-bypass
description: Researchers identified that Java’s certificate blocklist (blocked.certs) can be bypassed for compromised certificates by re-encoding them to produce different SHA-256 fingerprints while maintaining signature validity.
date: "2026-10-22T03:36:55Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - certificate-bypass
  - defense-evasion
  - java
  - supply-chain
vendors:
  - Oracle
products:
  - JDK
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553.004
    technique_name: Install Root Certificate
    evidence: A certificate blocklist can reject a known-bad certificate and still miss another encoding of it.
    confidence_band: high
references:
  - https://www.sonatype.com/blog/the-limits-of-fingerprint-blocklists-a-reproducible-java-certificate-bypass
  - https://emudhra.we-have-a-problem.com/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory JDK versions and associated trust stores currently in production.
      owner: IT Operations
      due: 48h
      evidence: Verify the protections in the runtimes and trust stores you deploy.
  mitigation_plan:
    - priority: immediate
      action: Remove roots associated with compromised eMudhra intermediates from Java trust stores.
      owner: Security Engineering
      addresses: eMudhra CA compromise
      evidence: Removing the relevant roots rejected both chains in our tests.
---

Sonatype researchers confirmed that Java's `blocked.certs` mechanism, used to mitigate the October 2026 eMudhra certificate authority compromise, is susceptible to bypass. Because the blocklist relies on exact SHA-256 byte-level fingerprints, attackers can alter the binary encoding of a compromised certificate without invalidating its signature. If the re-encoded certificate is still accepted by the trust store, it bypasses the blocklist. This was demonstrated using both ECDSA (altering signature representation from *s* to *n-s*) and RSA (removing NULL parameters from signature algorithm identifiers) encodings.

## Impact
The bypass allows compromised intermediate CA certificates to remain trusted in Java environments even if their original fingerprints are added to `blocked.certs`. This could facilitate the issuance and acceptance of fraudulent certificates by applications relying on the Java trust store, despite vendor-provided mitigation attempts.

## Recommendation
- Audit Java runtime trust stores to identify and remove root certificates associated with the compromised eMudhra infrastructure rather than relying solely on the `blocked.certs` file.
- Test certificate chain validation for critical services using both original and potential re-encoded variants of compromised intermediates.
- Monitor Java application logs for TLS handshake failures or unusual certificate validation outcomes following updates to trust stores.
- Coordinate with infrastructure and development teams before modifying trust stores to avoid disrupting legitimate TLS connections.
