---
title: Unbounded Decryption SpinCount Denial of Service in Excelize
slug: 2026-10-excelize-dos
description: An unbounded key-derivation loop in the Excelize library allows an attacker to trigger CPU exhaustion via a maliciously crafted EncryptionInfo stream in an OLE-formatted file.
date: "2026-10-07T22:53:15Z"
lastmod: "2026-10-08T19:26:53Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:xuri:excelize:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - Go
  - excelize
vendors:
  - xuri
products:
  - excelize (>= 2.3.1, < 2.11.1-0.20260906004932-2badfcd5841d)
  - excelize (>= 2.8.1, < 2.11.1-0.20261003002531-6258dcebc4e2)
  - excelize (< 2.11.1-0.20260930021559-01a9ff32fb3c)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker can craft a malicious file with a high spinCount value in the EncryptionInfo stream, forcing the application to perform excessive CPU-intensive key derivation calculations.
    confidence_band: high
cves:
  - id: CVE-2026-107219
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-jrfj-fhj2-jjvm
  - https://github.com/advisories/GHSA-mx22-3794-2vpv
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107211
  - https://github.com/advisories/GHSA-jw42-f3rr-4cc3
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107212
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Excelize to version 2.11.1-0.20260906004932-2badfcd5841d
      owner: IT Operations
      due: 48h
      evidence: Source explicitly mandates upgrading to this fixed version to address CVE-2026-107219.
  mitigation_plan:
    - priority: short_term
      action: Implement request timeout and CPU monitoring for any application service using Excelize to parse user files.
      owner: Application Security
      addresses: CVE-2026-107219
      evidence: The source notes that the operation lacks context and cannot be cancelled by the caller.
updates:
  - at: "2026-10-08T19:25:47Z"
    level: L1
    summary: added coverage for excelize (>= 2.8.1, < 2.11.1-0.20261003002531-6258dcebc4e2)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-mx22-3794-2vpv
  - at: "2026-10-08T19:26:53Z"
    level: L1
    summary: added coverage for excelize (< 2.11.1-0.20260930021559-01a9ff32fb3c)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-jw42-f3rr-4cc3
---

The Excelize Go library (versions 2.3.1 through 2.11.0) contains a denial-of-service vulnerability triggered by the lack of bounds checking on the `spinCount` parameter during the agile decryption process. The library branches into the decryption routine based solely on the first eight bytes of a file (the OLE magic number), regardless of whether the file is legitimately encrypted or if the application supports encrypted workbooks. 

The `crypt.go` module reads the `spinCount` value directly from the XML-unmarshaled `EncryptionInfo` stream without validation. An attacker can supply an arbitrarily large integer for `spinCount`, forcing the `convertPasswdToKey` function to perform a CPU-intensive key derivation loop for that many iterations. Because the operation does not accept a `context.Context`, it cannot be canceled by the caller, leading to prolonged CPU exhaustion that persists even after the calling application hits request timeouts. The vulnerability impacts any application using Excelize to parse untrusted OLE files.

## Attack Chain

1. Attacker crafts a malicious file, ensuring the first eight bytes match the OLE magic number to trigger the Excelize file-parsing routine.
2. Attacker embeds a crafted `EncryptionInfo` stream within the file structure.
3. Attacker sets the `spinCount` element in the XML stream to a high integer value (e.g., 100,000,000+).
4. Victim application attempts to open the file using `excelize.OpenFile`.
5. `openReaderAt` detects the OLE header and invokes `agileDecrypt` without verifying if the file requires decryption.
6. `agileDecrypt` calls `convertPasswdToKey`, which initiates a long-running loop based on the attacker-controlled `spinCount`.
7. The process consumes CPU resources linearly, causing high load and blocking the goroutine from returning, resulting in an effective Denial of Service for the application instance.

## Impact

Successful exploitation results in a Denial of Service (DoS) for the application processing the file. Since the operations run independently of the caller context, resources remain locked until the loop finishes, potentially exhausting server CPU resources if multiple malicious files are submitted concurrently. This vulnerability primarily affects applications that process user-uploaded Excel files (e.g., web-based document converters, data analysis tools, or enterprise reporting portals).

## Recommendation

Prioritized actions for development and security teams:
- Upgrade the Excelize library to version 2.11.1-0.20260906004932-2badfcd5841d or later to implement proper bounds checking on the `spinCount` value.
- Implement file-size or process-time limits at the application layer for all file parsing routines that utilize Excelize, as the library does not natively support context-based cancellation.
- Scan incoming files for the OLE magic number (first 8 bytes) and validate the `EncryptionInfo` stream structure before passing the file to the `excelize` library in high-exposure environments.
