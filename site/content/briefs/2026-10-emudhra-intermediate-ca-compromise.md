---
brief_id: brief-2026-10-21-emudhra-intermediate-ca-compromise
event_id: brief-2026-10-21-emudhra-intermediate-ca-compromise
revision: 1
activity_at: "2026-10-21T14:19:28Z"
title: eMudhra Intermediate Certificate Authority Compromise (CVE-2026-111943)
slug: 2026-10-emudhra-intermediate-ca-compromise
description: The compromise of eight eMudhra intermediate certificate authority private keys due to a flawed key-generation process allows for the issuance of fraudulent, trusted certificates, necessitating urgent patches across programming language runtimes and browsers.
date: "2026-10-21T14:19:28Z"
lastmod: "2026-10-22T03:37:05Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Advisory confirmed by BSI; no specific CVEs were listed in the source provided.
tags:
  - vulnerability
  - browser
  - client-side
  - pki
  - certificate-authority
  - supply-chain
  - tls
  - infrastructure-security
  - informational
vendors:
  - Mozilla
  - eMudhra
  - Go
  - Python
  - Rust
  - Sonatype
products:
  - Firefox
  - Firefox ESR
  - Thunderbird
  - Go (< 1.26.10, < 1.27.3)
  - Firefox (< 158.0.1, < ESR 115.43.1, < ESR 153.5.1)
  - NSS (< 3.131.1)
  - certifi
  - webpki-roots (< 1.0.10)
  - Sonatype products and distributions
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1588.004
    technique_name: Digital Certificates
    evidence: Private keys associated with eight eMudhra intermediate certificate authority certificates were compromised, potentially allowing unauthorized parties to create certificates that could appear trustworthy to vulnerable clients.
    confidence_band: high
cves:
  - id: CVE-2026-111943
    epss: 0.00145
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4064
  - https://socprime.com/blog/cve-2026-111943-analysis/
  - https://blog.talosintelligence.com/compromised-intermediate-certificates/
  - https://www.sonatype.com/blog/emudhra-ca-incident-sonatypes-assessment-and-guidance
  - https://guide.sonatype.com/security-event/6a82b8e8-2715-4157-956b-ddcca5014b57
iocs:
  - type: hash_sha256
    value: E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838
  - type: hash_sha256
    value: 98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B
  - type: hash_sha256
    value: 42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493
  - type: hash_sha256
    value: 432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3
  - type: hash_sha256
    value: CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F
  - type: hash_sha256
    value: 0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19
  - type: hash_sha256
    value: 9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4
  - type: hash_sha256
    value: 4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1
ioc_counts:
  hash_sha256: 8
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Firefox, Firefox ESR, and Thunderbird to the latest versions provided by the vendor.
      owner: IT Operations
      addresses: General product vulnerabilities
      evidence: Mozilla security advisory
updates:
  - at: "2026-10-21T14:21:49Z"
    level: L2
    summary: added coverage for Go (< 1.26.10, < 1.27.3) +4 products
    sources:
      - socprime
    source_urls:
      - https://socprime.com/blog/cve-2026-111943-analysis/
  - at: "2026-10-21T20:58:22Z"
    level: L2
    summary: added CVE-2026-111943
    sources:
      - talos
    source_urls:
      - https://blog.talosintelligence.com/compromised-intermediate-certificates/
  - at: "2026-10-22T03:37:05Z"
    level: L1
    summary: added coverage for Sonatype products and distributions
    sources:
      - sonatype
    source_urls:
      - https://www.sonatype.com/blog/emudhra-ca-incident-sonatypes-assessment-and-guidance
---

On October 17, 2026, a security researcher identified that eight intermediate certificate authorities operated by eMudhra possessed insecurely generated private keys, which could be independently recovered. This compromise allows an attacker to issue fraudulent, trusted TLS and code-signing certificates. While there is no evidence of widespread abuse prior to defensive actions, the severity of the cryptographic failure prompted immediate revocation and denylisting efforts across browsers and language runtimes. The Go Project released CVE-2026-111943 to hardcode a denylist of the affected keys in the crypto/x509 library to protect applications that do not rely on system-level certificate revocation mechanisms.

## Impact

An attacker in possession of the compromised intermediate keys could potentially impersonate legitimate websites, intercept encrypted traffic, or sign malicious code. The risk is highest for applications that manage independent certificate bundles or runtimes that do not consume browser-based revocation lists like CRLSet or OneCRL.

## Recommendation

- Upgrade Go environments to version 1.26.10, 1.27.3, or later and rebuild all compiled applications to incorporate the new cryptographic denylist.
- Update Firefox to version 158.0.1, ESR 115.43.1, or ESR 153.5.1 and ensure NSS is patched to 3.131.1 or later.
- Audit and update software dependencies that maintain embedded certificate bundles, specifically Python's 'certifi' and Rust's 'webpki-roots' (ensure version 1.0.10 or newer).
- Monitor certificate chain telemetry for the presence of the eight identified compromised intermediate CA public keys.
