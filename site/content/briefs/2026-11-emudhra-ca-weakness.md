---
brief_id: brief-2026-11-05-emudhra-ca-weakness
event_id: brief-2026-11-05-emudhra-ca-weakness
revision: 1
activity_at: "2026-11-05T03:43:09Z"
title: 'eMudhra/emSign: Weak Intermediate CA Private Keys (CVE-2026-111943)'
slug: 2026-11-emudhra-ca-weakness
description: Eight eMudhra/emSign intermediate CA certificates were generated with weak P-384 ECC private keys, allowing attackers to forge valid TLS and code-signing certificates and perform seamless Man-in-the-Middle attacks.
date: "2026-11-05T03:43:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
vendors:
  - eMudhra
  - Python
  - Go
  - Node.js
  - Electron
  - Rust
  - Bun
  - Debian
  - Ubuntu
  - Alpine
  - Oracle
  - Apple
  - Microsoft
  - Google
products:
  - certifi (< 2026.10.19)
  - pip (< 26.2.2)
  - Go (< 1.27.3 / < 1.26.10)
  - Node.js (< 26.12.1 / < 24.22.1 / < 22.23.4)
  - Electron (< 44.9.1 / < 43.8.1 / < 42.11.16)
  - rustls-webpki (< 0.103.16)
  - webpki-roots (< 1.0.10)
  - Bun (< 1.4.4)
  - sigstore (< 4.5.1)
  - ca-certificates
  - NSS (< 3.131.1)
  - Java (cacerts)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588.004
    technique_name: Digital Certificates
    evidence: Eight eMudhra/emSign intermediate CA certificates were created in April 2025 with P-384 ECC keys where the private scalar d was a tiny integer.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1573.002
    technique_name: Asymmetric Cryptography
    evidence: 'MITM Attacks: Forge valid TLS certificates for any hostname — intercept HTTPS traffic from clients with unpatched trust stores'
    confidence_band: high
cves:
  - id: CVE-2026-111943
    cvss: 6.8
    epss: 0.00396
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111943
  - https://emudhra.we-have-a-problem.com
  - https://sploitus.com/exploit?id=BBD230AF-B94E-517E-91BD-B4D8E7EDB150
  - https://sploitus.com/exploit?id=BBD230AF-B94E-517E-91BD-B4D8E7EDB150&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch all internal instances of Python certifi, Go, Node.js, and OS-level ca-certificates using the fixed versions identified in section 2.
      owner: IT Operations
      due: 24h
      evidence: Vulnerable non-browser software requires updates to CA bundles and trust stores.
  hunt_leads:
    - lead: Identify TLS connections within the environment presenting certificates issued by the compromised eMudhra intermediates.
      technique_id: T1573.002
      data_needed:
        - Zeek or SSL/TLS inspection logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Zeek package emudhra-weak-keys detects affected certificates in TLS handshakes.
  mitigation_plan:
    - priority: immediate
      action: Update Java cacerts by blocking the 16 SHA-256 hashes provided in section 7 of the brief.
      owner: IT Operations
      addresses: Java vulnerabilities
      evidence: 'For Java: add 16 SHA-256 hashes to $JAVA_HOME/lib/security/blocked.certs'
---

Eight eMudhra/emSign intermediate CA certificates created in April 2025 utilized P-384 ECC keys with trivially small private scalars (d in {4, 56, 66, 115, 155, 156, 230, 237}). Because these scalars are so small, the private key can be recovered from the public certificate in milliseconds. Six of the compromised intermediates could mint TLS certificates for any hostname, while two functioned as code-signing CAs. While major browsers (Chrome, Firefox, Safari) and OS vendors (Microsoft, Apple) have pushed blocks, non-browser software and environments relying on bundled or outdated CA trust stores remain vulnerable.

## Attack Chain

1. Recovery: Attacker extracts the public key from an affected intermediate certificate and performs a brute-force search across the 8 known scalar candidates to derive the private key.
2. Forgery: Attacker generates a new leaf key pair and signs a certificate for any target hostname (CN/SAN) using the recovered CA private key.
3. MITM Setup: Attacker deploys a TLS server configured with the forged certificate chain.
4. Redirection: Attacker forces victim traffic to the MITM server (e.g., via DNS poisoning or ARP spoofing).
5. Interception: Victim client connects; because the trust store is unpatched, it validates the forged certificate, allowing the attacker to decrypt and inspect all TLS traffic.
6. Post-exploitation: Attacker injects malicious payloads, steals credentials, or establishes persistent C2 channels via the compromised connection.

## Impact

Successful exploitation allows for the interception of HTTPS traffic (MITM), deployment of trusted phishing sites for any domain, and the creation of valid-looking code-signing certificates to sign malware. All traffic protected by software using unpatched CA bundles or trust stores is subject to decryption.

## Recommendation

- Update CA trust stores and cryptographic libraries immediately: Python certifi (2026.10.19+), pip (26.2.2+), Go (1.27.3/1.26.10+), and Node.js (22.23.4/24.22.1/26.12.1+).
- Add the 16 SHA-256 hashes of the compromised CA certificates to the `blocked.certs` list for all Java environments.
- Rebuild containers and binaries that bundle trust stores (e.g., Debian/Ubuntu/Alpine/RHEL-based images).
- Scan internal PKI and trust stores for the specific root certificate fingerprints listed in section 7 of the source.
