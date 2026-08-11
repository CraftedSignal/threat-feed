---
title: Arbitrary File Exfiltration in DSPy Image and Audio Adapters (CVE-2026-72742)
slug: 2026-08-dspy-exfiltration
description: DSPy version 3.3.0b1 is vulnerable to arbitrary local file exfiltration via path traversal in its Image and Audio field adapters, allowing an attacker to read and transmit sensitive file contents.
date: "2026-08-11T21:50:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - exfiltration
  - library-vulnerability
  - dspy
vendors:
  - DSPy
products:
  - DSPy (3.3.0b1)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The JSONAdapter and ChatAdapter parse untrusted language model completions... which triggers encode_image or encode_audio to read and base64-encode any local file path via the os.path.isfile branch
    confidence_band: high
cves:
  - id: CVE-2026-72742
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72742
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade DSPy to the latest patched version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-72742
  mitigation_plan:
    - priority: immediate
      action: Review and restrict application filesystem permissions
      owner: IT Operations
      addresses: CVE-2026-72742
      evidence: Arbitrary local file read vulnerability
---

DSPy version 3.3.0b1 contains a critical path traversal vulnerability in the Image and Audio output field adapters. This vulnerability arises when the library parses untrusted language model completions. If an attacker can influence the model's output - typically through prompt injection or a compromised upstream language model - they can supply a malicious filesystem path within the 'url' field of an Image or Audio typed output.

The library's JSONAdapter and ChatAdapter components pass these outputs through the parse_value and TypeAdapter validation functions. These subsequently trigger encode_image or encode_audio routines in image.py and audio.py. These functions utilize the os.path.isfile check to determine if the provided path is a valid file, then proceed to read and base64-encode the contents. The resulting data is then embedded into outgoing prompts or API responses sent to an attacker-controlled language model endpoint, effectively exfiltrating local system files.

## Impact

The vulnerability poses a severe risk of data exfiltration, allowing unauthorized access to any file readable by the user context running the DSPy-based application. Depending on the environment, this may include configuration files, credentials, source code, or sensitive data stored on the filesystem. As this relies on LLM output influence, any application using DSPy to process external or untrusted model completions is at risk of remote exploitation.

## Recommendation

1. Upgrade all instances of DSPy to a version where this vulnerability is remediated.
2. Implement strict input validation and sandboxing for all responses returned by external language models to prevent the injection of arbitrary filesystem paths.
3. Restrict the operating system privileges of the application process to the minimum necessary for normal operation to mitigate the scope of files accessible via this traversal flaw.
