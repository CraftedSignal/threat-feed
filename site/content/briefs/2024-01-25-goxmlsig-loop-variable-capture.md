---
title: goxmlsig Vulnerability CVE-2026-33487 Loop Variable Capture
slug: 2024-01-25-goxmlsig-loop-variable-capture
description: A vulnerability exists in goxmlsig versions prior to 1.6.0 related to loop variable capture in the `validateSignature` function when using older Go versions, leading to incorrect signature validation.
date: "2024-01-25T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xml
  - signature-bypass
  - vulnerability
vendors:
  - goxmlsig
products:
  - goxmlsig
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33487
rules:
  - title: Detect goxmlsig Validation Errors
    description: Detects potential signature validation errors in goxmlsig applications based on logged error messages indicative of validation failure.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
  - title: Detect goxmlsig using an old Go version
    description: Detects goxmlsig processes running under a Go version older than 1.22 which are vulnerable to CVE-2026-33487.
    platform: sigma
    severity: low
    tactics:
      - vulnerability
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The goxmlsig library, which provides XML Digital Signatures implemented in Go, is vulnerable to a loop variable capture issue in versions prior to 1.6.0. Specifically, the `validateSignature` function in `validate.go` iterates through references in the `SignedInfo` block to match the signed element's ID. In Go versions before 1.22, or when `go.mod` uses an older version, the code incorrectly takes the address of the loop variable `_ref` instead of its value. This results in the `ref` pointer potentially always pointing to the last element in the `SignedInfo.References` slice after the loop, especially if multiple references match the ID or if the loop logic is flawed. The vulnerability, identified as CVE-2026-33487, can lead to signature validation bypass. goxmlsig version 1.6.0 addresses this vulnerability with a patch.

## Attack Chain

1. An attacker crafts a malicious XML document with a digital signature.
2. The crafted XML document is submitted to a Go application using goxmlsig for signature validation.
3. The `validateSignature` function in `validate.go` is invoked.
4. The function iterates through the `SignedInfo.References` slice.
5. Due to the loop variable capture issue (CVE-2026-33487), the `ref` pointer incorrectly points to the last element in the slice, especially if running Go versions older than 1.22.
6. The incorrect `ref` pointer leads to a mismatch during signature verification.
7. Despite the signature being invalid, the validation may incorrectly pass due to the flawed logic.
8. The application processes the malicious XML document as if it were genuinely signed, leading to potential data corruption or unauthorized actions.

## Impact

Successful exploitation of this vulnerability allows an attacker to bypass signature validation in applications using goxmlsig. This can lead to severe consequences such as processing of untrusted or tampered XML data. The vulnerability has a CVSS v3.1 base score of 7.5, indicating a high impact. This could potentially impact any application relying on goxmlsig for secure XML processing, leading to data integrity compromise or unauthorized access to sensitive information.

## Recommendation

*   Upgrade the goxmlsig library to version 1.6.0 or later to patch CVE-2026-33487.
*   When using goxmlsig, ensure the Go version is 1.22 or higher to avoid the loop variable capture issue.
*   Implement additional validation checks on the processed XML data to detect potential tampering, even after signature validation.
*   Monitor the applications logs for error or unexpected behavior during XML signature validation using goxmlsig.
