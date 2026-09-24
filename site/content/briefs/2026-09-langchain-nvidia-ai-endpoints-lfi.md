---
title: Local File Disclosure in langchain-nvidia-ai-endpoints
slug: 2026-09-langchain-nvidia-ai-endpoints-lfi
description: The langchain-nvidia-ai-endpoints library versions prior to 1.4.2 are vulnerable to local file disclosure when attacker-controlled image inputs are passed to ChatNVIDIA or VLM reranking APIs, leading to unauthorized file reading and exfiltration to remote endpoints.
date: "2026-09-24T20:06:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:langchain:langchain-nvidia-ai-endpoints:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - local-file-inclusion
  - python
  - supply-chain
vendors:
  - LangChain
products:
  - langchain-nvidia-ai-endpoints (< 1.4.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who can control those inputs may be able to read local files accessible to the application process.
    confidence_band: high
cves:
  - id: CVE-2024-34812
    cvss: 5.3
    epss: 0.00585
references:
  - https://github.com/advisories/GHSA-g28h-2cmm-rj9x
  - https://nvd.nist.gov/vuln/detail/CVE-2024-34812
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade langchain-nvidia-ai-endpoints to 1.4.2 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory states 1.4.2 resolves the vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Implement strict input validation to block local filesystem paths in VLM image inputs.
      owner: Application Security
      addresses: CVE-2024-34812
      evidence: Source documentation for workarounds.
---

The `langchain-nvidia-ai-endpoints` Python package, specifically versions 1.4.1 and earlier, contains a local file disclosure vulnerability. The issue arises from the package's handling of Vision Language Model (VLM) image inputs, where the library fails to adequately sanitize or restrict image paths provided to the `ChatNVIDIA` or VLM reranking APIs. 

If an application utilizing this library allows untrusted user input to influence the image source parameter, an attacker can supply local filesystem paths. When the library processes these requests, it treats the provided path as a file to be read by the application process. The contents of these files are then included in the payload sent to the configured NVIDIA/NIM model backend. This allows attackers to exfiltrate arbitrary files that the application process has permissions to read, such as configuration files, local credentials, or source code. The vulnerability was addressed in version 1.4.2, which strictly filters input types to only permit remote URLs, base64-encoded data URIs, and authorized asset identifiers.

## Impact

Applications built with `langchain-nvidia-ai-endpoints` that process untrusted image inputs are at risk of arbitrary file disclosure. If exploited, an attacker can gain unauthorized access to sensitive local files, which may lead to further exploitation, credential theft, or exposure of internal infrastructure details. The potential impact depends on the filesystem permissions assigned to the service account running the application process.

## Recommendation

- Upgrade `langchain-nvidia-ai-endpoints` to version 1.4.2 or later immediately.
- If patching is delayed, implement strict server-side validation to reject any user-supplied image input that resembles a local filesystem path (e.g., paths starting with `/`, `C:\`, or relative path traversal sequences like `../`).
- Enforce the principle of least privilege for the application process; ensure the service account running the application has read access restricted only to the files and directories strictly necessary for its operation.
- Review application logs for anomalous requests to the `ChatNVIDIA` or reranking endpoints that contain suspicious local path string patterns in image parameters.
