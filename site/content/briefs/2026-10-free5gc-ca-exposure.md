---
brief_id: brief-2026-10-29-free5gc-ca-exposure
event_id: brief-2026-10-29-free5gc-ca-exposure
revision: 1
activity_at: "2026-10-29T21:25:06Z"
title: 'free5gc: Root CA Private Key Exposure (CVE-2026-115925)'
slug: 2026-10-free5gc-ca-exposure
description: The free5gc core network implementation ships with a hard-coded Root CA private key, enabling attackers to forge certificates for network function impersonation in HTTPS-enabled environments.
date: "2026-10-29T21:25:06Z"
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
  validation_status: Needs environment validation of certificate usage in local deployments.
cpes:
  - cpe:2.3:a:free5gc:free5gc:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - 5g
  - cryptographic-vulnerability
  - hardcoded-keys
vendors:
  - free5gc
products:
  - free5gc (v1.0.0 – v4.2.3+)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: The free5gc repository ships an unencrypted Root Certificate Authority (CA) private key at cert/root.key.
    confidence_band: high
cves:
  - id: CVE-2026-115925
    kev_status: unknown
references:
  - https://github.com/free5gc/free5gc/security/advisories/GHSA-grjj-c27p-3mgc
  - https://sploitus.com/exploit?id=11B20D0B-5261-5918-A871-857AF44034E1
  - https://sploitus.com/exploit?id=11B20D0B-5261-5918-A871-857AF44034E1&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - Network Infrastructure
  immediate_actions:
    - action: Audit all free5gc instances to determine if HTTPS/mTLS is enabled in the SBI configuration.
      owner: Network Infrastructure
      due: 24h
      evidence: The only documented path to harden SBI (switching http to https) makes root.key the live trust anchor.
  hunt_leads:
    - lead: Search for unauthorized access or modification to the cert/ directory in free5gc deployment paths.
      technique_id: T1552.001
      data_needed:
        - File system audit logs
        - SIEM file integrity monitoring alerts
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The key is hard-coded and present in the source repository at cert/root.key.
  mitigation_plan:
    - priority: immediate
      action: Rotate the Root CA private key and update all network function certificates in the 5G core.
      owner: Network Infrastructure
      addresses: CVE-2026-115925
      evidence: 'Remediation: Remove key, gitignore, per-deployment CA.'
---

The free5gc repository includes a hard-coded Root CA private key located at 'cert/root.key' and 'NFs/bsf/cert/root.key'. While the vulnerability is dormant in default configurations that use HTTP, the key becomes the active trust anchor for network function (NF) to network function (NF) mTLS when operators enable HTTPS to harden the Service Based Architecture (SBI). This allows an attacker to forge certificates and perform Man-in-the-Middle (MITM) attacks. No patches are currently available; remediation requires manual rotation of the CA.

## Impact

Successful exploitation allows an attacker to gain full control over the PKI trust chain, facilitating the impersonation of any network function within the 5G core. This results in complete compromise of confidentiality and integrity for inter-NF traffic.

## Recommendation

- Identify all free5gc deployments within your environment, specifically those configured to use HTTPS/mTLS for the Service Based Architecture (SBI).
- Immediately rotate the Root CA for all affected deployments; do not rely on the default keys provided in the source repository.
- Apply strict access control policies to the filesystem where the free5gc certificate store resides to prevent unauthorized extraction of the 'root.key' file.
- Implement a manual certificate rotation procedure that generates unique keys per deployment rather than utilizing the static key provided by the vendor.
