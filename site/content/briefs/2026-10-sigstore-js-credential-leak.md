---
brief_id: brief-2026-10-29-sigstore-js-credential-leak
event_id: brief-2026-10-29-sigstore-js-credential-leak
revision: 1
activity_at: "2026-10-29T17:53:20Z"
title: 'Sigstore-js: Registry credential disclosure (CVE-2026-118763)'
slug: 2026-10-sigstore-js-credential-leak
description: The sigstore-js library prior to 0.7.2 fails to validate OCI registry redirect origins in RegistryClient.uploadBlob(), allowing compromised registries to perform unauthorized exfiltration of authentication headers to attacker-controlled hosts.
date: "2026-10-29T17:53:20Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified vendor fix exists
cpes:
  - cpe:2.3:a:sigstore:sigstore-js:*:*:*:*:*:*:*:*
tags:
  - credential-theft
  - oci
  - supply-chain-security
vendors:
  - Sigstore
products:
  - sigstore-js (< 0.7.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: A malicious or compromised registry can therefore direct a user pushing an artifact through attachArtifactToImage() to an attacker-controlled host and receive the registry bearer token, Basic credentials, or custom authentication headers.
    confidence_band: high
cves:
  - id: CVE-2026-118763
    cvss: 7.4
    kev_status: "false"
  - id: CVE-2026-59891
    cvss: 9.6
    epss: 0.00473
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118763
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade sigstore-js to 0.7.2 in all application dependencies
      owner: IT Operations
      due: 48h
      evidence: Version 0.7.2 fixes the issue by separating registry credentials from client-wide defaults
  hunt_leads:
    - lead: Search for outgoing HTTP PUT requests from build agents or servers originating from sigstore-js processes to unexpected domains
      technique_id: T1552.001
      data_needed:
        - Network flow logs or proxy logs recording destination host
        - Process information for outgoing connections
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The RegistryClient.uploadBlob() sends a fresh PUT to an absolute blob-upload Location supplied by the registry without checking that its origin or scheme matches the registry.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to sigstore-js 0.7.2
      owner: IT Operations
      addresses: CVE-2026-118763
      evidence: Version 0.7.2 fixes the issue by separating registry credentials from client-wide defaults
---

The sigstore-js library, specifically the `RegistryClient.uploadBlob()` method, contains a vulnerability where it fails to constrain the destination of requests to an OCI registry's specified upload location. An attacker who controls or compromises an OCI registry can return a malicious blob-upload URL. When the library attempts to upload an artifact, it sends a PUT request to the attacker's host, including credentials (bearer tokens, Basic auth, or custom headers) originally intended for the legitimate registry. This vulnerability is a residual issue from CVE-2026-59891, where previous fixes were insufficient to scope credentials to the registry origin. Version 0.7.2 addresses this by isolating credentials and enforcing origin matching.

## Impact

Successful exploitation allows for the theft of sensitive authentication credentials, including bearer tokens and Basic credentials used for registry access.

## Recommendation

- Upgrade sigstore-js to version 0.7.2 or later immediately.
- Review registry interaction logs for instances where `attachArtifactToImage()` requests result in redirects or cross-origin POST/PUT operations to non-registry domains.
- If using sigstore-js within CI/CD pipelines, ensure the registry host configuration follows the principle of least privilege and verify that CI secrets are scoped to specific registry endpoints.
