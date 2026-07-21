---
title: Sigstore/OCI Credential Confusion Vulnerability (CVE-2026-59891)
slug: 2026-07-sigstore-oci-credential-confusion
description: A critical credential exposure vulnerability (CVE-2026-59891) exists in `@sigstore/oci` versions prior to 0.7.1. The `getRegistryCredentials()` function, used to read credentials from `~/.docker/config.json`, employs a substring match instead of an exact host match when selecting credentials. This flaw allows credentials for a legitimate registry (e.g., `ghcr.io`) to be inadvertently transmitted to an attacker-controlled registry if its hostname is a substring of the legitimate one (e.g., `cr.io`). This impacts consumers of `@sigstore/oci` and related GitHub Actions (`actions/attest`, `actions/attest-build-provenance`, `actions/attest-sbom`) when pushing artifacts to untrusted or attacker-influenced destination registries, potentially leading to the leakage of long-lived registry tokens. The vulnerability is fixed in `@sigstore/oci@0.7.1` by enforcing exact host matching.
date: "2026-07-21T19:35:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - credential-exposure
  - vulnerability
  - github-actions
  - docker
  - supply-chain
vendors:
  - Sigstore
  - GitHub
products:
  - '@sigstore/oci < 0.7.1'
  - actions/attest
  - actions/attest-build-provenance
  - actions/attest-sbom
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: '`getRegistryCredentials()` reads credentials from the Docker config file (`~/.docker/config.json`)'
    confidence_band: high
cves:
  - id: CVE-2026-59891
    cvss: 9.6
    epss: 0.00321
references:
  - https://github.com/advisories/GHSA-pf56-329r-95rw
---

A critical credential exposure vulnerability, tracked as CVE-2026-59891, has been identified in `@sigstore/oci` versions `<= 0.7.0`. This flaw resides within the `getRegistryCredentials()` function, which is responsible for retrieving OCI registry authentication tokens from the Docker configuration file (`~/.docker/config.json`). The vulnerability stems from an insecure credential selection mechanism that uses a substring match instead of a precise host match. This means that credentials configured for a legitimate registry (e.g., `ghcr.io`) could be mistakenly associated with, and subsequently transmitted to, an attacker-controlled registry if its hostname is a substring of the legitimate one (e.g., `cr.io`). This impacts any application using `@sigstore/oci` to upload artifacts, including `@actions/attest` and the `actions/attest`, `actions/attest-build-provenance`, and `actions/attest-sbom` GitHub Actions, particularly when the destination registry or image reference (`subject-name` input) can be influenced by untrusted sources. This could lead to the leakage of long-lived registry tokens to malicious actors. The vulnerability was patched in `@sigstore/oci@0.7.1`, which implements exact host matching.

## Attack Chain

1. An attacker identifies a target system utilizing `@sigstore/oci` (or GitHub Actions like `actions/attest`) for pushing artifacts to OCI registries.
2. The attacker researches or infers that the target system has configured credentials for a legitimate OCI registry (e.g., `ghcr.io`) stored in its `~/.docker/config.json`.
3. The attacker registers or gains control over a malicious OCI registry with a hostname that is a substring of the legitimate registry's hostname (e.g., `cr.io` for `ghcr.io`).
4. The attacker influences the target system to push artifacts to the attacker-controlled registry by manipulating the destination registry or image reference. In the context of GitHub Actions, this might involve influencing the `subject-name` input when `push-to-registry: true`.
5. During the artifact push operation, the `@sigstore/oci` library calls `getRegistryCredentials()` to retrieve authentication.
6. Due to the substring matching logic, `getRegistryCredentials()` incorrectly selects the credentials intended for `ghcr.io` (because `cr.io` is a substring).
7. The `@sigstore/oci` library then transmits these long-lived registry credentials to the attacker-controlled registry (`cr.io`).
8. The attacker captures the stolen registry credentials, gaining unauthorized access to the legitimate registry.

## Impact

The primary impact of CVE-2026-59891 is the potential exposure of sensitive, long-lived OCI registry credentials. Any consumer of `@sigstore/oci` or related GitHub Actions (such as `actions/attest`, `actions/attest-build-provenance`, and `actions/attest-sbom`) that pushes artifacts using credentials from a Docker configuration file is susceptible. While no specific victim count is provided, the theoretical worst-case scenario involves the theft of valuable authentication tokens, granting attackers unauthorized access to artifact repositories, enabling supply chain attacks, or facilitating further lateral movement. Exploitation requires specific conditions: credentials in the Docker config, untrusted influence over the destination registry, and an attacker-controlled registry with a substring hostname.

## Recommendation

* **Patch CVE-2026-59891 immediately**: Upgrade `@sigstore/oci` to version `0.7.1` or later to fix the credential selection logic.
* **Update GitHub Actions**: Ensure that your GitHub Actions workflows using `actions/attest`, `actions/attest-build-provenance`, or `actions/attest-sbom` are updated to versions that bundle the patched `@sigstore/oci` library.
* **Validate input**: Treat the destination registry/image reference as trusted input; do not allow untrusted sources to influence the registry/image reference passed to `@sigstore/oci` or the `subject-name` of `actions/attest*` when `push-to-registry: true`.
* **Limit `~/.docker/config.json` credentials**: Restrict the credentials available in the host's Docker config file (`~/.docker/config.json`) to only those strictly necessary for operations, and avoid authenticating to registries whose hostnames could have substring relationships with potential untrusted destinations.
* **Scope tokens narrowly**: Prefer using narrowly scoped and short-lived registry tokens to minimize the impact of potential credential leakage.
