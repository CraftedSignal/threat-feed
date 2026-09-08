---
title: Critical Remote Code Execution Vulnerabilities in libheif Affecting Sharp
slug: 2026-09-sharp-libheif-vulnerabilities
description: Multiple critical vulnerabilities in the libheif library, including CVE-2026-84383, enable potential remote code execution via malicious AVIF image processing in applications using the sharp npm package.
date: "2026-09-08T21:50:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:struktur:libheif:*:*:*:*:*:*:*:*
  - cpe:2.3:a:sharp_project:sharp:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - rce
  - image-processing
  - library-vulnerability
vendors:
  - Struktur
  - Sharp
products:
  - libheif (< 1.23.2)
  - sharp (< 0.35.4)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The vulnerabilities can lead to possible remote code execution on glibc-based Linux when run under certain conditions.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-rgj7-g3m4-5g8c
  - https://github.com/strukturag/libheif/security/advisories/GHSA-g89c-p67h-r497
  - https://github.com/strukturag/libheif/security/advisories/GHSA-2jg2-4ch7-h545
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84383
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade sharp to version 0.35.4 or later across all applications.
      owner: IT Operations
      due: 24h
      evidence: Most people rely on the prebuilt binaries provided by sharp. Please upgrade sharp to the latest version, currently 0.35.4.
    - action: Deploy the sharp.block workaround for applications handling untrusted HEIF/AVIF uploads where patching is delayed.
      owner: Application Security
      due: 24h
      evidence: Add the following to your code to prevent sharp from decoding AVIF images.
  mitigation_plan:
    - priority: immediate
      action: Verify Node.js runtime is compiled as a PIE binary.
      owner: IT Operations
      addresses: RCE exploitation mitigation
      evidence: Ensure you are using a node executable binary compiled as a Position Independent Executable.
---

Security researchers have identified multiple critical vulnerabilities within the libheif library, a dependency used by the sharp npm package for image processing. The vulnerabilities, notably tracked as CVE-2026-84383, arise during the parsing of HEIF/AVIF image formats. If an application using an affected version of sharp processes a specially crafted, malicious AVIF image, it can trigger memory corruption leading to potential remote code execution (RCE) on glibc-based Linux systems. 

The impact is contingent on how the application handles untrusted image input. While the upstream libheif vulnerability is classified as critical, the sharp package maintainers have downgraded the severity to high as sharp itself does not provide native networking features. However, the risk remains significant for any system that ingests and processes images from external or untrusted sources. Users are strongly urged to upgrade to sharp version 0.35.4 or later, which incorporates the patched libheif version 1.23.2.

## Impact

Successful exploitation could result in full remote code execution on the underlying host operating system. This vulnerability affects any service or infrastructure utilizing the sharp npm package (versions prior to 0.35.4) to decode HEIF/AVIF image files. Targeted sectors include web applications, content management systems, and image processing pipelines that accept user-submitted files.

## Recommendation

* Upgrade all instances of the sharp npm package to version 0.35.4 or later immediately.
* For environments unable to update immediately, apply the code-level blocklist to disable HEIF/AVIF decoding: sharp.block({ operation: ["VipsForeignLoadHeif"] });.
* Ensure the Node.js runtime environment is compiled as a Position Independent Executable (PIE) to provide exploit mitigations against RCE attempts, noting that official Node.js binaries may lack this configuration by default.
* Audit image processing pipelines to identify and isolate services currently handling untrusted AVIF or HEIF file uploads.
