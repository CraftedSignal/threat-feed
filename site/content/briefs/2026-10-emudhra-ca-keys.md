---
brief_id: brief-2026-10-21-emudhra-ca-keys
event_id: brief-2026-10-21-emudhra-ca-keys
revision: 2
activity_at: "2026-10-21T12:20:28Z"
revision_history:
  - revision: 2
    at: "2026-10-21T13:09:06Z"
    checksum: sha256:ab845900720aee4f102e4d9b5b4489b83f037d20aef071eca6dbd32658a21b03
    summary: Retired this duplicate public page in favor of the consolidated eMudhra incident brief.
    changed_fields:
      - draft
    maintenance: true
draft: true
title: 'eMudhra: Intermediate Certificate Authority private key recovery'
slug: 2026-10-emudhra-ca-keys
description: Eight eMudhra intermediate certificates were issued with insufficient cryptographic entropy, allowing the private keys to be easily recovered and used to impersonate trusted websites.
date: "2026-10-21T12:20:28Z"
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
  validation_status: Source-verified; environment validation required to ensure all legacy trust stores are cleared.
tags:
  - certificate-authority
  - supply-chain
  - cryptography
vendors:
  - eMudhra
products:
  - Intermediate Certificate Authorities
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588.004
    technique_name: Digital Certificates
    evidence: The certificates were issued in April 2025, and some of the compromised keys could allow attackers to generate fraudulent certificates and impersonate any website.
    confidence_band: high
references:
  - https://www.securityweek.com/browsers-block-emudhra-intermediate-cas-over-recoverable-private-keys/
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Remove compromised eMudhra CA certificates from enterprise trust stores
      owner: IT Operations
      due: 24h
      evidence: Root programs and trust stores have started blocking them.
  hunt_leads:
    - lead: Identify endpoints or internal applications still trusting the revoked eMudhra certificates
      technique_id: T1588.004
      data_needed:
        - Trust store configuration files
        - TLS/SSL certificate monitoring data
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Some clients may require software updates to ensure that the compromised intermediates are no longer trusted.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied updates or manual revocation to remove trust in the eight identified intermediate CAs
      owner: IT Operations
      addresses: Intermediate Certificate Authorities
      evidence: eMudhra revoked the compromised certificates, and the issue was communicated to downstream trust stores.
---

The Indian certificate authority eMudhra issued eight intermediate CA certificates in April 2025 containing critical cryptographic flaws. Due to a failure in the key generation ceremony script, these certificates were generated with insufficient entropy, resulting in private keys that are effectively all-zeroes except for the final byte. This weakness allows the private keys to be recovered nearly instantaneously using the baby-step giant-step discrete log algorithm. While no evidence of malicious exploitation exists in Certificate Transparency logs, the vulnerability theoretically allowed for the forgery of trusted HTTPS certificates to impersonate any website. Major root programs (Mozilla, Google, Apple, Microsoft) have blocked these certificates, and eMudhra has revoked them.

## Impact

The vulnerability permitted the unauthorized generation of fraudulent, trusted HTTPS certificates. This facilitates man-in-the-middle attacks, enabling attackers to intercept, decrypt, or manipulate encrypted traffic for any domain by presenting a forged certificate that clients would accept as valid.

## Recommendation

- Identify and remove the compromised eMudhra intermediate certificates from all enterprise trust stores and internal PKI management tools.
- Utilize the validation tool provided by Mozilla (Dennis Jackson) to audit client environments for remaining trust in these compromised intermediates.
- Prioritize patching and software updates for all systems, as some clients require updates to ensure these specific intermediates are no longer trusted.
- Review eMudhra's forthcoming audit of their key generation ceremony processes to ensure internal compliance and risk management alignment.
