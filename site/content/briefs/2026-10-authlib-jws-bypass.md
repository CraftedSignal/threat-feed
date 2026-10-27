---
brief_id: brief-2026-10-27-authlib-jws-bypass
event_id: brief-2026-10-27-authlib-jws-bypass
revision: 1
activity_at: "2026-10-27T17:53:57Z"
title: 'Authlib: Signature verification bypass in JWS JSON deserialization'
slug: 2026-10-authlib-jws-bypass
description: Authlib versions prior to 1.9.0 contain a signature verification bypass vulnerability. The JsonWebSignature.deserialize_json() method returns the payload as successfully verified when provided with a JWS JSON Serialization object containing an empty signatures array, without checking for a signature or requiring a cryptographic key.
date: "2026-10-27T17:53:57Z"
lastmod: "2026-10-27T17:54:36Z"
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
  validation_status: Source-verified
cpes:
  - cpe:2.3:a:authlib:authlib:*:*:*:*:*:*:*:*
  - cpe:2.3:a:authlib:authlib:*:*:*:*:*:python:*:*
tags:
  - authlib
  - authentication-bypass
  - jws-vulnerability
  - jwt
  - crypto-vulnerability
  - python
vendors:
  - Authlib
products:
  - Authlib (prior to 1.9.0)
  - Authlib (< 1.9.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550.002
    technique_name: Pass the Hash
    evidence: An attacker who knows (or can cause) the application to verify a token with an empty key can forge arbitrary tokens that pass HS256/HS384/HS512 signature verification.
    confidence_band: high
cves:
  - id: CVE-2026-96760
    cvss: 9.8
    epss: 0.00383
    kev_status: "false"
  - id: CVE-2026-114616
    cvss: 7.4
    epss: 0.00212
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-6v38-4h7w-rj9h
  - https://github.com/advisories/GHSA-8m4g-j4wp-wgcg
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114616
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Authlib dependencies to 1.9.1 or later
      owner: IT Operations
      due: 48h
      evidence: Authlib advisory reports version 1.9.1 as the fixed release
  hunt_leads:
    - lead: Identify applications using Authlib for JWT verification that source secret keys from environment variables or configuration files prone to defaulting to empty values.
      technique_id: T1550.002
      data_needed:
        - Application dependency manifests (requirements.txt, pyproject.toml)
        - Code review of JWT secret retrieval logic
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'The realistic trigger matches the sibling CVEs: the deploying application sources the verification key from a place that can be empty at runtime.'
  mitigation_plan:
    - priority: immediate
      action: Implement explicit length validation for all HMAC keys used with Authlib.
      owner: Detection Engineering
      addresses: CVE-2026-114616
      evidence: Reject empty oct key material in OctKey.import_key, exactly as the maintainer's joserfc library already does.
updates:
  - at: "2026-10-27T17:54:36Z"
    level: L2
    summary: added coverage for Authlib (< 1.9.1)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-8m4g-j4wp-wgcg
---

Authlib versions prior to 1.9.0 contain a vulnerability in the `JsonWebSignature.deserialize_json()` method. Due to an implementation error where a validation flag is initialized as `True` and never toggled if the `signatures` array is empty, the library treats payloads as verified without signature or key validation. This allows an unauthenticated caller to bypass authentication or authorization checks when processing forged JWS JSON objects.
