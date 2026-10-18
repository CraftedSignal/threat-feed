---
title: Heap Out-of-Bounds Write Vulnerability in cgltf
slug: 2026-10-cgltf-heap-corruption
description: The cgltf library through version 1.15 is susceptible to a heap out-of-bounds write vulnerability via maliciously crafted glTF or GLB files, potentially leading to arbitrary code execution.
date: "2026-10-18T12:22:03Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cgltf_project:cgltf:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
products:
  - cgltf (<= 1.15)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attacker can supply a crafted glTF or GLB file with large sparse indices to corrupt heap memory, crash applications, and potentially execute code when cgltf_validate() is not called.
    confidence_band: high
cves:
  - id: CVE-2026-112018
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112018
action_plan:
  priority: elevated
  owners:
    - Development
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade or patch cgltf to version 1.16 or later
      owner: Development
      addresses: CVE-2026-112018
      evidence: Source states that the vulnerability exists through 1.15.
---

The cgltf library, a lightweight glTF 2.0 loader, contains a heap out-of-bounds write vulnerability in versions up to and including 1.15. The issue resides within the cgltf_accessor_unpack_floats() function. An attacker can exploit this by providing a specially crafted glTF or GLB file containing unchecked sparse accessor indices. When parsed by an application using the vulnerable cgltf library, these large indices cause the loader to write data outside the intended output buffer, corrupting heap memory. This can result in an immediate application crash (DoS) or, in certain memory layouts, allow an attacker to gain control over application execution flow. The risk is particularly elevated in applications that fail to call the cgltf_validate() function before processing the data, as the library does not inherently enforce strict bounds checking on these indices.

## Impact

Successful exploitation can lead to a denial of service through application crashes or arbitrary code execution within the context of the vulnerable host process. Given that cgltf is a common component in 3D rendering engines, game engines, and graphics processing tools, the potential attack surface includes any software that processes untrusted 3D assets, such as web browsers, 3D model viewers, and game assets pipelines.

## Recommendation

Prioritized actions for development and security engineering teams:
- Update any software utilizing the cgltf library to version 1.16 or later, where the input validation for sparse accessor indices has been improved.
- Review all integrations of the cgltf library to ensure the mandatory execution of cgltf_validate() on all untrusted input files before they reach the unpacking or processing stage.
- Audit custom parsers that incorporate cgltf code for the absence of pre-processing validation.
