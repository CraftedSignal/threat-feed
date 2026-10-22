---
brief_id: brief-2026-10-21-emudhra-cert-compromise
event_id: brief-2026-10-21-emudhra-cert-compromise
revision: 1
activity_at: "2026-10-21T07:57:21Z"
title: 'eMudhra: Intermediate certificate private key compromise'
slug: 2026-10-emudhra-cert-compromise
description: Mozilla identified the compromise of private keys for eight eMudhra intermediate certificates, which could allow attackers to issue fraudulent HTTPS certificates for arbitrary domains to conduct man-in-the-middle attacks.
date: "2026-10-21T07:57:21Z"
lastmod: "2026-10-22T19:01:06Z"
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
  validation_status: Source-verified
tags:
  - certificate-compromise
  - supply-chain
  - pki
  - supply-chain-security
  - certificate-authority
  - infrastructure-integrity
vendors:
  - eMudhra
products:
  - eMudhra intermediate certificates
  - Firefox (<= 158.0.0)
  - Firefox ESR (< 115.43.1)
  - Firefox ESR (< 153.5.1)
  - NSS (< 3.131.1)
  - eMudhra Intermediate Certificates (issued April 2025 – October 2026)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.004
    technique_name: Private Keys
    evidence: Mozilla received a report that private keys associated with eight eMudhra intermediate certificates had been compromised.
    confidence_band: high
references:
  - https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/
  - https://www.firefox.com/en-US/firefox/158.0.1/releasenotes/
  - https://groups.google.com/a/mozilla.org/g/dev-tech-crypto/c/vSxZxnOMMvs
  - https://therecord.media/indian-tech-company-announces-withdrawal-certificate-business-incident
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Update enterprise-managed Firefox and NSS-dependent applications to the versions identified in the brief
      owner: IT Operations
      due: 48h
      evidence: Mozilla security advisory specifies these versions distribute revocation protection.
  mitigation_plan:
    - priority: immediate
      action: Upgrade NSS library to 3.131.1
      owner: Security Engineering
      addresses: NSS trust store vulnerabilities
      evidence: Updating the trusted certificate list in NSS to remove the root certificate.
updates:
  - at: "2026-10-22T19:01:06Z"
    level: L2
    summary: added coverage for eMudhra Intermediate Certificates (issued April 2025 – October 2026)
    sources:
      - therecord
    source_urls:
      - https://therecord.media/indian-tech-company-announces-withdrawal-certificate-business-incident
---

On October 17, 2026, Mozilla confirmed that private keys associated with eight eMudhra intermediate certificates were compromised. These keys allow an attacker to issue fraudulent HTTPS certificates for websites they do not control, enabling the interception and modification of encrypted traffic (Man-in-the-Middle). 

Mozilla implemented mitigations via OneCRL, a centralized certificate revocation list, for all standard Firefox configurations. Additionally, Mozilla released Firefox 158.0.1, Firefox ESR 115.43.1, and Firefox ESR 153.5.1 to provide protections for users with custom configurations, and updated the NSS library (version 3.131.1) to remove the root certificate that signed the affected intermediates.

## Impact

The compromise of these intermediate keys allows an attacker capable of intercepting a user connection to impersonate any website, potentially exposing sensitive user data or allowing the injection of malicious content into HTTPS sessions.

## Recommendation

- Update all instances of Firefox to 158.0.1 (Desktop/Android) or the latest ESR versions (115.43.1 / 153.5.1) to ensure revocation coverage for custom configurations.
- Organizations utilizing the NSS (Network Security Services) library should update to version 3.131.1 or later to ensure the affected root certificate is untrusted.
- Audit infrastructure that relies on the eMudhra trust store for certificate validation.
