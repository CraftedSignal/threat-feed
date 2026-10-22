---
brief_id: brief-2026-10-21-litellm-compromise
event_id: brief-2026-10-21-litellm-compromise
revision: 1
activity_at: "2026-10-21T14:21:38Z"
title: LiteLLM Supply Chain Compromise
slug: 2026-10-litellm-compromise
description: A malicious version of the LiteLLM Python package (v1.107.0) was distributed via PyPI and Docker, containing credential theft functionality and dormant command-and-control capabilities.
date: "2026-10-21T14:21:38Z"
lastmod: "2026-10-22T09:35:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
tags:
  - supply-chain
  - credential-theft
  - python
vendors:
  - BerriAI
products:
  - LiteLLM (1.107.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Compromise Software Supply Chain
    subtechnique_name: Compromise Software Dependencies
    evidence: A malicious version (1.107.0) of the LiteLLM package was uploaded to PyPI and Docker on October 21.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    subtechnique_name: Python
    evidence: These packages are designed to be executed whenever a python interpreter is started.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.010
    technique_name: AppInit DLLs
    subtechnique_name: Python Boot Scripts
    evidence: Upon startup, the interpreter processes cook.pth, which includes a command to import cook, which loads cook.py.
    confidence_band: high
references:
  - https://www.wiz.io/blog/litellm-compromised-steals-credentials
  - https://www.reddit.com/r/blueteamsec/comments/1xbp4ez/security_litellm_11070_compromised_pypi_removed/
  - https://thehackernews.com/2026/10/litellm-suspects-github-token-leak-in.html
iocs:
  - type: url
    value: http://www.litellm.dev/healthcheck
  - type: hash_sha256
    value: 7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d
  - type: hash_sha256
    value: 0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a
  - type: hash_sha256
    value: 668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6
  - type: hash_sha256
    value: 462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7
  - type: hash_sha256
    value: c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054
  - type: hash_sha256
    value: 1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00
  - type: hash_sha256
    value: 12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484
  - type: hash_sha256
    value: bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5
  - type: hash_sha256
    value: 56b74573eed6e4aafe4b50603dbe7853e0345f188c8e44a09f1098caf1f4bcdf
  - type: domain
    value: litellm.dev
  - type: ip
    value: 168.100.8.57
  - type: ip
    value: 165.227.201.8
ioc_counts:
  domain: 1
  hash_sha256: 9
  ip: 2
  url: 1
rules:
  - title: Detect Malicious LiteLLM Package Artifacts
    description: Detects the creation of known malicious python files associated with LiteLLM v1.107.0 in site-packages directories
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1546.010
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - CTI
    - Detection Engineering
  immediate_actions:
    - action: Block traffic to www.litellm.dev
      owner: SOC
      due: 1h
      evidence: Exfiltration endpoint for stolen secrets
  mitigation_plan:
    - priority: immediate
      action: Uninstall LiteLLM 1.107.0 and revert to version 1.106.2
      owner: IT Operations
      addresses: LiteLLM (1.107.0)
      evidence: The most recent safe version is v1.106.2.
updates:
  - at: "2026-10-22T09:35:47Z"
    level: L1
    summary: new IOCs
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/10/litellm-suspects-github-token-leak-in.html
---

On October 21, 2026, version 1.107.0 of the LiteLLM package was identified as malicious on PyPI and Docker registries. The package contained embedded malicious scripts (`cook.pth`, `cook.py`, and `sitecustomize.py`) designed to execute automatically upon Python interpreter initialization. These scripts perform credential harvesting and attempt to establish command-and-control communication.

## Attack Chain
1. Compromised LiteLLM package (v1.107.0) is installed via PyPI or pulled from Docker registries.
2. Python interpreter initializes, triggering the execution of `cook.pth` which imports `cook.py`.
3. `cook.py` runs an obfuscated credential-stealer routine targeting browser, cloud, and AI secrets.
4. Stolen credentials are encrypted and exfiltrated to an attacker-controlled endpoint (`www.litellm.dev/healthcheck`).
5. On Linux and macOS systems, `sitecustomize.py` attempts to fetch a secondary stage payload URL from a GitHub dead drop.
6. The second-stage script, if retrieved, would be downloaded and executed on the host.

## Impact
The malicious package successfully harvested system, browser, developer, cloud, and AI tool secrets from compromised environments. The exfiltration endpoint was configured to receive this sensitive data via HTTP POST requests.

## Recommendation
- Immediately audit environments for the presence of LiteLLM v1.107.0 and downgrade to the known safe version (v1.106.2).
- Review network logs for egress traffic to `www.litellm.dev` or communication attempts with GitHub-hosted dead drops from Python processes.
- Rotate all credentials (cloud, AI, browser-stored) that may have been present in environments where the malicious package was executed.
- Scan file systems for the artifacts `cook.pth`, `cook.py`, and `sitecustomize.py` in Python site-packages directories.
