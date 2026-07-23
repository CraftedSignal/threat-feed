---
title: CVE-2026-65918 - PyTorch Torchvision Out-of-Bounds Heap Read Vulnerability
slug: 2026-07-pytorch-torchvision-oob-read
description: An out-of-bounds heap read vulnerability (CVE-2026-65918) in PyTorch torchvision through version 0.28.0 allows attackers to supply malicious GIF files, leading to denial of service via segmentation fault or disclosure of adjacent heap memory contents.
date: "2026-07-23T18:24:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - information-disclosure
  - library-vulnerability
vendors:
  - PyTorch
products:
  - torchvision (through 0.28.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can supply malicious or truncated GIF files... (Implies delivery mechanism often involves user interaction, as indicated by CVSS UI:R)
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Attackers can supply malicious or truncated GIF files to cause denial of service via segmentation fault or disclose adjacent heap memory contents.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can supply malicious or truncated GIF files to cause denial of service via segmentation fault
    confidence_band: high
cves:
  - id: CVE-2026-65918
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65918
  - https://github.com/pytorch/vision/commit/4e05dc22f5f050a9528cc0ea09ceca6cdaf8f4ed
  - https://github.com/pytorch/vision/issues/9551
  - https://github.com/pytorch/vision/pull/9520
  - https://www.vulncheck.com/advisories/pytorch-torchvision-gif-decoder-out-of-bounds-heap-read
---

A critical out-of-bounds heap read vulnerability, identified as CVE-2026-65918, affects PyTorch's `torchvision` library up to and including version 0.28.0. This flaw resides within the GIF decoder's `read_from_tensor` callback, which inadvertently passes an unchecked (unclamped) length value to the `memcpy` function. This oversight enables attackers to craft and supply malicious or truncated GIF files. When a vulnerable application processes these files, the uncontrolled memory access can lead to a denial of service (DoS) through a segmentation fault, causing the application to crash. Furthermore, the vulnerability could potentially allow for the disclosure of sensitive data residing in adjacent heap memory regions. The issue was addressed in commit `4e05dc2`. This vulnerability is particularly concerning for applications that process untrusted image inputs, as successful exploitation could lead to application instability or sensitive information exposure.

## Attack Chain

1. **Attacker crafts malicious GIF**: An attacker develops a specially crafted or truncated GIF file designed to exploit the out-of-bounds read vulnerability in the `PyTorch torchvision` library.
2. **Delivery of malicious GIF**: The attacker delivers the malicious GIF to a target system. This could occur via various vectors, such as an email attachment, a malicious website download, or embedded within a web application where `torchvision` processes user-supplied images.
3. **Processing by vulnerable application**: A software application utilizing the vulnerable `PyTorch torchvision` library (version 0.28.0 or earlier) attempts to process the malicious GIF file for tasks like display, analysis, or transformation.
4. **`read_from_tensor` callback execution**: During the GIF decoding process, the `read_from_tensor` callback function within `torchvision` is invoked to handle the image data from the malicious file.
5. **Out-of-bounds read via `memcpy`**: Within the `read_from_tensor` callback, an unclamped (unchecked) length value is passed to the `memcpy` function, triggering an attempt to read data beyond the boundaries of the allocated heap buffer.
6. **Denial of Service (DoS)**: The out-of-bounds read operation results in a segmentation fault, causing the application to crash and rendering it unavailable, leading to a denial of service.
7. **Information Disclosure**: In some scenarios, instead of a crash, the out-of-bounds read may disclose sensitive data from adjacent heap memory regions. This leaked information could then be potentially exfiltrated or leveraged by the attacker for further exploitation.

## Impact

Successful exploitation of CVE-2026-65918 can lead to a high impact on the availability and confidentiality of systems using vulnerable versions of `PyTorch torchvision`. The primary observed damage includes denial of service, characterized by application crashes due to segmentation faults, disrupting normal operations. Depending on the memory layout and the nature of the data, exploitation could also lead to the disclosure of adjacent heap memory contents, potentially exposing sensitive information processed by the application. While the NVD does not specify victim counts or targeted sectors, any application that processes untrusted GIF files using `PyTorch torchvision` through version 0.28.0 is at risk.

## Recommendation

* **Patch CVE-2026-65918 immediately**: Update `PyTorch torchvision` to a version beyond 0.28.0 that includes commit `4e05dc22f5f050a9528cc0ea09ceca6cdaf8f4ed` to remediate the vulnerability.
* **Monitor for application crashes**: Implement monitoring for unexpected process terminations or segmentation faults in applications utilizing `PyTorch torchvision` as a potential indicator of attempted exploitation, even though this is not specific to CVE-2026-65918.
