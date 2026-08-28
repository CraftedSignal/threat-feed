---
title: Path Traversal and Trust Inheritance Vulnerability in gitoxide
slug: 2026-08-gitoxide-path-traversal
description: A path traversal and trust inheritance vulnerability in the gitoxide Rust crates allows attackers to access arbitrary git configurations by crafting malicious .gitmodules files.
date: "2026-08-28T15:13:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - supply-chain
  - gitoxide
  - rust
vendors:
  - gitoxide
products:
  - gix (<= 0.72.0)
  - gix-validate (<= 0.10.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An attacker can craft a malicious .gitmodules file so that a victim tool built on gitoxide reads arbitrary git repository configuration (including embedded credentials).
    confidence_band: high
cves:
  - id: CVE-2026-82253
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82253
action_plan:
  priority: elevated
  owners:
    - Development Teams
    - DevSecOps
  mitigation_plan:
    - priority: immediate
      action: Upgrade gix to 0.82.0 and gix-validate to 0.11.1
      owner: Development Teams
      addresses: CVE-2026-82253
      evidence: Fixed in gix 0.82.0 and gix-validate 0.11.1.
---

The gitoxide project (gix and gix-validate crates) contains a path traversal vulnerability that, when combined with an insecure trust inheritance flaw in Submodule::open(), allows an attacker to compromise repositories using these libraries. The validation function in gix-validate only checks for the first occurrence of '..' in submodule names, which can be bypassed using crafted strings such as 'a..b/../../../.git/'. Furthermore, this validation is not invoked in active code paths. The vulnerability is amplified by a trust inheritance flaw in Submodule::open(), where parent repository trust levels (Trust::Full) are incorrectly propagated to submodules, bypassing ownership verification and safe-directory protections. An attacker can craft a malicious .gitmodules file to force applications using gitoxide to read arbitrary repository configurations, potentially exposing embedded credentials or executing actions with unintended privileges. The vulnerability was addressed in gix version 0.82.0 and gix-validate version 0.11.1.

## Impact

Successful exploitation allows for the reading of sensitive git repository configurations, including embedded credentials, potentially impacting any software built on the affected versions of the gitoxide ecosystem. It bypasses established safe-directory security mechanisms, increasing the risk of unauthorized repository access or data exfiltration in development environments or CI/CD pipelines.

## Recommendation

Update all projects using the gitoxide library to the patched versions immediately. Developers should audit usage of Submodule::open() and ensure that inputs from external .gitmodules files are sanitized before processing.

- Upgrade the gix crate to version 0.82.0 or later.
- Upgrade the gix-validate crate to version 0.11.1 or later.
- Audit repositories for unusually formatted entries in .gitmodules files, specifically those containing directory traversal sequences.
