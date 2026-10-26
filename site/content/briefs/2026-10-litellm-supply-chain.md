---
brief_id: brief-2026-10-21-litellm-supply-chain
event_id: brief-2026-10-21-litellm-supply-chain
revision: 2
activity_at: "2026-10-26T12:57:14Z"
revision_history:
  - revision: 2
    at: "2026-10-26T12:57:14Z"
    checksum: sha256:16c950002d5c95b077beece3fb95349f8e04f2af4c7377f4f2289d6ed6a86053
    summary: exploited:true
    changed_fields:
      - exploitation_evidence
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://therecord.media/litellm-hackers-ai-malware
title: 'LiteLLM: Supply chain compromise of version 1.107.0'
slug: 2026-10-litellm-supply-chain
description: The LiteLLM Python package version 1.107.0 was compromised via stolen GitHub CLI OAuth tokens to distribute a credential-stealing backdoor that harvests cloud and developer secrets.
date: "2026-10-21T19:06:48Z"
lastmod: "2026-10-26T12:56:40Z"
type: advisory
types:
  - advisory
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://therecord.media/litellm-hackers-ai-malware
  observed_at: "2026-10-26T12:00:00Z"
  confidence: medium
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Source corroborated by multiple security firms.
tags:
  - supply-chain
  - python
  - credential-theft
  - malware
vendors:
  - LiteLLM
products:
  - LiteLLM (1.107.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Compromise Software Supply Chain
    evidence: The popular LiteLLM Python package has been compromised as part of a software supply chain attack.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: The malware is launched by Python even before LiteLLM is imported through a path file ('cook.pth'), which is designed to automatically execute code when the interpreter starts.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1552.001
    technique_name: Credentials In Files
    evidence: This includes harvesting cloud tokens, developer accounts and private keys, AI tooling credential JSON files, browser data associated with Chromium and Firefox, and environment variables.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: The collected data is packaged into a GZIP-compressed TAR archive and sent to 'litellm[.]dev/healthcheck' by means of an HTTP POST request.
    confidence_band: high
references:
  - https://thehackernews.com/2026/10/litellm-compromised-in-supply-chain.html
  - https://therecord.media/litellm-hackers-ai-malware
iocs:
  - type: url
    value: https://litellm.dev/healthcheck
ioc_counts:
  url: 1
rules:
  - title: Detect Malicious LiteLLM Path File
    description: Detects the creation or presence of the malicious cook.pth file used by the LiteLLM 1.107.0 backdoor to execute code on interpreter startup.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory all systems for LiteLLM 1.107.0
      owner: IT Operations
      due: 4h
      evidence: The compromise affects LiteLLM 1.107.0
    - action: Revoke credentials present on systems that ran LiteLLM 1.107.0
      owner: Security Engineering
      due: 12h
      evidence: Malware collects cloud credentials, private keys, browser data, and authentication files
  hunt_leads:
    - lead: Search for presence of 'cook.pth' in Python site-packages directories
      technique_id: T1059.003
      data_needed:
        - EDR file monitoring
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The malware is launched by Python ... through a path file ('cook.pth')
  mitigation_plan:
    - priority: immediate
      action: Pin LiteLLM version to 1.106.2 using integrity digests
      owner: Development
      addresses: LiteLLM 1.107.0
      evidence: Users who have downloaded the malicious version are advised to ... pin version 1.106.2 by digest.
updates:
  - at: "2026-10-26T12:56:40Z"
    level: L3
    summary: exploited:true
    sources:
      - therecord
    source_urls:
      - https://therecord.media/litellm-hackers-ai-malware
---

LiteLLM version 1.107.0 was identified as malicious, having been distributed via PyPI and Docker images containing unauthorized code. The compromise occurred through the theft of GitHub CLI OAuth tokens belonging to three project engineers, which allowed the threat actor to trigger and approve a malicious release. All affected tokens have been revoked, and the organization is currently migrating to a more secure account management structure.

## Attack Chain

1. Threat actor obtains GitHub CLI OAuth tokens belonging to three project engineers.
2. Threat actor uses one compromised account to trigger a project-releaser run.
3. Threat actor uses a second compromised account to approve the malicious release.
4. Malicious LiteLLM 1.107.0 package is published to PyPI and Docker Hub.
5. User installs or updates the malicious LiteLLM package.
6. Python interpreter loads the malicious 'cook.pth' file upon startup.
7. 'cook.pth' triggers the 'privcollect' payload to harvest cloud tokens, keys, and browser data.
8. Background daemon checks a GitHub-hosted dead drop for further instructions and executes returned Python code.

## Impact

Successful exploitation results in the unauthorized exfiltration of cloud credentials, SSH private keys, browser data, and authentication files for various AI development tools. Collected data is exfiltrated as a GZIP-compressed TAR archive via HTTP POST requests to 'litellm.dev/healthcheck'.

## Recommendation

- Pin dependencies to version 1.106.2 using cryptographic digests to prevent accidental installation of compromised versions.
- Review all environments where LiteLLM 1.107.0 was installed for signs of credential harvesting or persistent backdoors.
- Revoke and rotate all cloud credentials, API keys, and certificates present on systems that ran version 1.107.0.
- Monitor Python environments for the presence of files named 'cook.pth' or usage of the 'cook' module, which are indicative of this specific malware.
- Implement supply chain security practices such as ephemeral build environments and restricted permissions for GitHub CLI tokens used in automated release pipelines.
