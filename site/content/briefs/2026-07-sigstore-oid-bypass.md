---
title: Sigstore `certificateOIDs` Verification Bypass Vulnerability (CVE-2026-48815)
slug: 2026-07-sigstore-oid-bypass
description: A high-severity vulnerability (CVE-2026-48815) in the `npm/sigstore` library (versions <= 4.1.0) causes the `certificateOIDs` verification constraint to be silently ignored, allowing applications to accept unauthorized certificates that should have been rejected based on extension policy, which could lead to supply chain attacks by trusting malicious artifacts.
date: "2026-07-03T12:37:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - supply-chain
  - software-security
  - javascript
  - npm
  - code-signing
vendors:
  - Sigstore
products:
  - npm/sigstore
references:
  - https://github.com/advisories/GHSA-52v5-jr5w-gjxr
---

A significant security vulnerability, identified as CVE-2026-48815, affects the `npm/sigstore` JavaScript library in versions up to and including 4.1.0. This flaw stems from a critical oversight in the library's certificate verification logic: while the public `sigstore.verify()` API accepts the `certificateOIDs` option, which is intended to enforce specific object identifiers (OIDs) within a certificate's extensions, this constraint is silently dropped during policy construction. Consequently, applications that rely on `certificateOIDs` to restrict accepted certificates for artifact signing are left without this crucial protection. An attacker could exploit this by presenting a certificate lacking the expected OIDs, yet still satisfying other verification checks, thereby bypassing a key policy enforcement mechanism and potentially enabling the trust of unauthorized or malicious software artifacts in a supply chain.

## Attack Chain

1.  **Attacker crafts malicious artifact**: An attacker creates a malicious software package or artifact intended for distribution.
2.  **Attacker obtains unauthorized signing certificate**: The attacker acquires a certificate that meets general validity criteria (e.g., correct issuer, valid dates) but *lacks* specific critical OID extensions that the target application's `sigstore` configuration *intends* to enforce via `certificateOIDs`.
3.  **Attacker signs malicious artifact**: The attacker signs the malicious artifact using their unauthorized certificate.
4.  **Target system attempts to verify artifact**: A target system, using a vulnerable `npm/sigstore` library (<= 4.1.0) and configured with `certificateOIDs` to enforce specific OID policies, attempts to verify the signed artifact.
5.  **`sigstore` silently drops OID constraints**: Due to the vulnerability, the `npm/sigstore` library's `createVerificationPolicy()` function silently ignores the `certificateOIDs` parameter when constructing the verification policy.
6.  **Artifact falsely deemed legitimate**: The signed malicious artifact passes `sigstore` verification because the critical OID extension check, which should have rejected the unauthorized certificate, was never applied.
7.  **Malicious artifact executed/deployed**: The target system proceeds to trust and potentially execute or deploy the malicious artifact, believing it to be legitimately signed and compliant with its security policies.

## Impact

Applications integrating the `npm/sigstore` library that depend on the `certificateOIDs` feature for robust certificate policy enforcement are rendered vulnerable to supply chain attacks. This vulnerability means that unauthorized or non-compliant certificates, which should be explicitly rejected based on missing or incorrect OID extensions, will instead be accepted by the verification process. The direct consequence is that organizations relying on this library for software supply chain integrity could inadvertently trust and deploy malicious artifacts. This could lead to a wide range of impacts, including system compromise, data exfiltration, or the introduction of backdoors, undermining the entire purpose of artifact signing and verification. The exact number of affected organizations is difficult to ascertain, but any user of `npm/sigstore` up to version 4.1.0 configured with `certificateOIDs` is at risk.

## Recommendation

*   **Patch CVE-2026-48815 immediately**: Upgrade `npm/sigstore` to a patched version (4.1.1 or later) to address CVE-2026-48815, ensuring `certificateOIDs` are correctly enforced during verification.
*   **Review `sigstore` configurations**: Audit all `sigstore.verify()` and `createVerifier()` calls in your codebase to confirm that certificate validation logic correctly identifies and rejects certificates that do not meet expected OID constraints, even after patching.
