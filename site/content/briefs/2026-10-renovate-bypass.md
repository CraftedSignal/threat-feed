---
title: Renovate Configuration Preset Allowlist Bypass
slug: 2026-10-renovate-bypass
description: An allowlist bypass in Renovate versions prior to 44.60.1 enables attackers to inject restricted environment variables via malicious configuration presets, leading to arbitrary code execution in child processes.
date: "2026-10-15T00:34:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mend:renovate:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - ci-cd
  - code-execution
vendors:
  - Mend
products:
  - Renovate (< 44.60.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An attacker controlling an externally sourced preset can override variables like PATH, LD_PRELOAD, NODE_OPTIONS, or GIT_SSL_CAINFO in child processes on self-hosted instances.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This allows for arbitrary code execution in child processes on self-hosted instances of Renovate.
    confidence_band: high
cves:
  - id: CVE-2026-110867
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110867
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Renovate to 44.60.1 or later
      owner: IT Operations
      due: 24h
      evidence: Renovate before 44.60.1 contains an allowlist bypass vulnerability
  mitigation_plan:
    - priority: immediate
      action: Restrict external preset sources to trusted repositories only
      owner: Security Engineering
      addresses: CVE-2026-110867
      evidence: Attackers controlling an externally sourced preset can override variables
---

Renovate versions prior to 44.60.1 contain an allowlist bypass vulnerability within its configuration preset system. An attacker who controls an externally sourced preset can override restricted environment variables such as PATH, LD_PRELOAD, NODE_OPTIONS, or GIT_SSL_CAINFO. This vulnerability is particularly dangerous for self-hosted Renovate instances where the software executes child processes to perform dependency management and dependency updates. By injecting malicious configuration, an attacker can manipulate the execution environment of these child processes, resulting in arbitrary code execution on the underlying host. The flaw arises from improper validation of preset contents, allowing arbitrary environment variable injection that bypasses existing security restrictions designed to prevent such modifications.
