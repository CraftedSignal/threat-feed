---
title: ONNX Path Traversal Vulnerability (CVE-2025-51480)
slug: 2026-05-onnx-path-traversal
description: CVE-2025-51480 is a path traversal vulnerability in ONNX 1.17.0 that allows attackers to overwrite arbitrary files by supplying crafted external_data.location paths containing traversal sequences.
date: "2026-05-23T07:59:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:linuxfoundation:onnx:1.17.0:*:*:*:*:*:*:*
tags:
  - path-traversal
  - file-overwrite
  - onnx
vendors:
  - Microsoft
  - ONNX
products:
  - ONNX 1.17.0
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1566
    technique_name: Impair System Integrity
cves:
  - id: CVE-2025-51480
    cvss: 8.8
    epss: 0.00366
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-51480
  - CVE-2025-51480
rules:
  - title: Detects CVE-2025-51480 Path Traversal attempt in ONNX external data helper
    description: Detects CVE-2025-51480 exploitation attempt using path traversal sequences in external_data.location
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2025-51480 Path Traversal attempt in ONNX external data helper via Python
    description: Detects CVE-2025-51480 exploitation attempt using path traversal sequences in external_data.location via Python interpreter
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2025-51480, exists within the onnx.external_data_helper.save_external_data component of ONNX (Open Neural Network Exchange) version 1.17.0. This flaw enables a malicious actor to overwrite arbitrary files on the system by crafting a specific external_data.location path. This crafted path incorporates traversal sequences (e.g., "../") which are designed to bypass intended directory restrictions. This vulnerability can be exploited if an attacker can control the external data location, potentially leading to arbitrary file overwrite and subsequent system compromise.

## Attack Chain

1. An attacker crafts a malicious ONNX model containing a specially crafted `external_data.location` path.
2. The crafted `external_data.location` path includes path traversal sequences (e.g., "../") to navigate outside the intended directory.
3. The attacker provides this malicious ONNX model to a system running ONNX 1.17.0.
4. The vulnerable `onnx.external_data_helper.save_external_data` function processes the malicious model.
5. Due to the path traversal vulnerability, the function bypasses intended directory restrictions.
6. The function attempts to save external data to the attacker-controlled path specified in the `external_data.location` field.
7. The attacker overwrites arbitrary files on the system with attacker-controlled data.

## Impact

Successful exploitation of CVE-2025-51480 allows an attacker to overwrite arbitrary files on the system where ONNX 1.17.0 is installed. This can lead to various malicious outcomes, including modification of critical system files, planting backdoors, or corrupting application data. The potential impact ranges from denial of service to complete system compromise, depending on the nature of the overwritten files.

## Recommendation

*   Upgrade to a patched version of ONNX that addresses CVE-2025-51480.
*   Apply input validation and sanitization to any user-supplied or external data used to construct file paths within ONNX models.
*   Deploy the Sigma rule detecting path traversal attempts to the webserver logs.
*   Monitor file system events for suspicious file overwrites, especially involving files referenced in the Sigma rule.
