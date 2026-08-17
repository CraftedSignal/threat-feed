---
title: Arbitrary Code Execution in openssl_encrypt Library
slug: 2026-08-openssl-encrypt-rce
description: The openssl_encrypt library before version 1.4.0 contains a vulnerability in its Whirlpool hash implementation that allows arbitrary code execution via untrusted shared object loading.
date: "2026-08-17T12:46:09Z"
lastmod: "2026-08-17T12:46:17Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - rce
  - python
  - supply-chain
vendors:
  - jahlives
products:
  - openssl_encrypt (< 1.4.0)
  - openssl_encrypt
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Attackers can place malicious .so files matching the whirlpool*py313*.so pattern in site-packages directories to achieve native code execution when the module is loaded.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can remove the jsonschema package or supply unknown metadata format versions to bypass all schema checks and process malicious data.
    confidence_band: high
cves:
  - id: CVE-2026-74872
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74872
  - https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-j48q-4c78-rhf9
  - https://www.vulncheck.com/advisories/openssl-encrypt-before-arbitrary-code-execution-via-whirlpool
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74875
  - https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-425g-fjhq-5h92
  - https://www.vulncheck.com/advisories/openssl-encrypt-before-schema-validation-bypass
rules:
  - title: Detect Creation of Suspicious Shared Objects in Site-Packages
    description: Detects the creation of files matching the malicious Whirlpool pattern in Python site-packages directories, indicative of CVE-2026-74872 exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1574.001
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update openssl_encrypt to 1.4.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-74872 patch release
  hunt_leads:
    - lead: Search file system for 'whirlpool*py313*.so' in site-packages
      technique_id: T1574.001
      data_needed:
        - File integrity logs or disk scan results
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CVE-2026-74872 description
updates:
  - at: "2026-08-17T12:46:17Z"
    level: L2
    summary: added coverage for openssl_encrypt
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74875
---

The openssl_encrypt Python package, specifically versions prior to 1.4.0, contains an arbitrary code execution vulnerability (CVE-2026-74872) located within its Whirlpool hash implementation. The library attempts to load shared object (.so) modules using overly broad glob patterns without performing any integrity or authenticity checks. An attacker capable of writing files to the Python site-packages directory can place a malicious shared object file that matches the pattern 'whirlpool*py313*.so'. When the openssl_encrypt library is imported or the specific hash function is invoked, the Python interpreter loads the malicious .so file, resulting in native code execution under the context of the running process. This issue is categorized as CWE-426: Untrusted Search Path.

## Impact

The vulnerability carries a CVSS v3.1 score of 9.8 (Critical). Successful exploitation allows unauthenticated remote or local attackers to achieve arbitrary code execution on systems where the library is present and the site-packages directory is writable. This exposes applications to full system compromise, data theft, and persistence, particularly in environments where automated installers or CI/CD pipelines might inadvertently grant attackers write access to site-packages.

## Recommendation

- Upgrade the 'openssl_encrypt' package to version 1.4.0 or later across all Python environments.
- Audit existing Python site-packages directories for any files matching the pattern 'whirlpool*py313*.so' that were not installed by the official package manager.
- Implement file integrity monitoring on Python library installation paths to detect unauthorized creation of .so files.
- Enforce strict file system permissions on 'site-packages' directories to prevent non-privileged users from modifying or adding library files.
