---
title: Node-Forge Certificate Chain Verification Bypass due to basicConstraints Violation
slug: 2026-07-node-forge-basic-constraints-bypass
description: Node-forge's certificate chain verification fails to enforce RFC 5280 basicConstraints, allowing leaf certificates without basicConstraints and keyUsage extensions to act as Certificate Authorities, leading to potential certificate forgery and man-in-the-middle attacks.
date: "2026-03-26T22:06:12Z"
severities:
  - high
tags:
  - certificate-forgery
  - man-in-the-middle
  - node-forge
  - basicConstraints
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-2328-f5f3-gj25
ioc_counts:
  url: 1
rules:
  - title: Detect Node-Forge Execution with Vulnerable Version
    description: Detects the execution of node-forge with a version vulnerable to the basicConstraints bypass vulnerability (CVE-2026-33896).
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Node-Forge Execution with Vulnerable Version (Linux)
    description: Detects the execution of node-forge with a version vulnerable to the basicConstraints bypass vulnerability (CVE-2026-33896) on Linux systems.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability exists in the node-forge npm package, specifically in versions 1.3.3 and earlier. The `pki.verifyCertificateChain()` function doesn't properly validate the `basicConstraints` extension during certificate chain verification, as specified in RFC 5280. When an intermediate certificate lacks both the `basicConstraints` and `keyUsage` extensions, the verification process incorrectly skips crucial checks, leading to the acceptance of the certificate as a valid CA. This allows…
