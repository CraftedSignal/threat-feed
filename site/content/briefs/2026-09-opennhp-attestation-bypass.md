---
title: Authentication Bypass in OpenNHP via Attestation Verification Manipulation
slug: 2026-09-opennhp-attestation-bypass
description: OpenNHP versions up to 1.0.2 contain an authentication bypass vulnerability allowing attackers to force the use of a fallback attestation verifier via malicious input.
date: "2026-09-16T21:57:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:opennhp:opennhp:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - attestation
  - security-flaw
vendors:
  - OpenNHP
products:
  - OpenNHP (<= 1.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers can bypass attestation verification by including the test_purpose key in evidence and providing enrolled measure and serial number pairs from the allowlist to gain unauthorized access.
    confidence_band: high
cves:
  - id: CVE-2026-92792
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92792
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenNHP to a version beyond 1.0.2 to remediate CVE-2026-92792.
      owner: IT Operations
      due: 48h
      evidence: Source identified the vulnerability in versions through 1.0.2.
  mitigation_plan:
    - priority: immediate
      action: Limit network access to attestation endpoints via firewall rules.
      owner: SOC
      addresses: CVE-2026-92792
      evidence: Vulnerability allows bypass of authentication via external input.
---

OpenNHP versions up to 1.0.2 are susceptible to an authentication bypass vulnerability involving the trusted-execution attestation process. The application insecurely selects its attestation verifier based on user-supplied evidence. Specifically, by injecting a 'test_purpose' key into the evidence payload, an attacker can force the application to default to the 'FallbackVerifier' regardless of the actual attestation context. By further providing enrolled measurement values and corresponding serial numbers - which may be obtained from existing allowlists - an attacker can satisfy the conditions required by the fallback logic. This flaw allows unauthorized entities to masquerade as valid devices or services, effectively bypassing the security controls intended to verify the integrity and identity of trusted execution environments. This vulnerability presents a high risk to environments relying on OpenNHP for identity and trust verification.

## Impact

Successful exploitation allows for the complete bypass of attestation-based authentication mechanisms within the OpenNHP framework. This grants unauthorized actors the ability to gain access to restricted network segments or services that rely on these verification checks, potentially leading to unauthorized data access, system manipulation, or further lateral movement within the network.

## Recommendation

1. Patch OpenNHP to the latest version available that addresses CVE-2026-92792 immediately.
2. If patching is not immediately feasible, restrict access to the attestation endpoints by implementing strict ingress filtering at the network level to limit the exposure of the management interface.
3. Audit application logs for anomalous attestation requests that include unusual keys such as 'test_purpose' in the payload.
