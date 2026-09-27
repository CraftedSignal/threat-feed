---
title: Remote Code Execution in MONAI Bundle Configuration Engine
slug: 2026-09-monai-rce
description: MONAI versions through 1.6.0 are vulnerable to remote code execution due to insecure deserialization and evaluation of arbitrary Python callables within bundle configuration files.
date: "2026-09-27T03:04:23Z"
lastmod: "2026-09-27T03:04:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:monai:monai:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - python
  - supply-chain
  - vulnerability
  - deserialization
  - rce
  - monai
vendors:
  - MONAI
products:
  - MONAI (<= 1.6.0)
  - MONAI (1.6.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can publish a malicious bundle with crafted configuration containing arbitrary code that executes when a victim loads the bundle using monai.bundle.load() or monai.bundle.run().
    confidence_band: high
cves:
  - id: CVE-2026-100840
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100840
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100841
action_plan:
  priority: elevated
  owners:
    - Security Operations
    - Development
  immediate_actions:
    - action: Upgrade all instances of MONAI to a version > 1.6.0
      owner: Development
      due: 24h
      evidence: CVE-2026-100840 remediates via patch
  mitigation_plan:
    - priority: immediate
      action: Restrict loading of external MONAI bundles to authorized repositories only
      owner: Security Operations
      addresses: CVE-2026-100840
      evidence: Source notes vulnerability in bundle configuration engine
updates:
  - at: "2026-09-27T03:04:32Z"
    level: L2
    summary: added coverage for MONAI (1.6.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100841
---

MONAI (Medical Open Network for AI) versions 1.6.0 and earlier contain a critical remote code execution (RCE) vulnerability within the bundle configuration engine. The vulnerability stems from the engine's failure to maintain an allow list when resolving '_target_' values to importable callables, combined with the unsafe passing of '$' expressions to the Python 'eval()' function. 

An attacker can exploit this by crafting a malicious bundle configuration file and distributing it to unsuspecting users. When a victim loads or executes this bundle using the affected 'monai.bundle.load()' or 'monai.bundle.run()' functions, the engine processes the malicious configuration, resulting in arbitrary code execution on the host system. This vulnerability poses a significant risk to researchers and developers who frequently download and integrate third-party AI bundles, as the malicious code triggers immediately upon processing the configuration.

## Impact

Successful exploitation allows for arbitrary code execution in the context of the Python interpreter running the MONAI environment. This could lead to full system compromise, exfiltration of sensitive medical imaging data, or lateral movement within research and development networks.

## Recommendation

- Immediately update MONAI to a version beyond 1.6.0.
- Avoid loading MONAI bundles from untrusted sources or repositories.
- Inspect bundle configuration files ('bundle.json' or similar) for unexpected '_target_' definitions or embedded '$' expressions before execution.
- Implement monitoring for child processes spawned by Python interpreter instances running MONAI-related tasks.
