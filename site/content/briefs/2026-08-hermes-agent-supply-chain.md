---
title: Hermes Agent Supply Chain Vulnerability via Mutable MCP Catalog References
slug: 2026-08-hermes-agent-supply-chain
description: Hermes Agent versions prior to 0.19.0 contain a supply chain vulnerability where the bundled MCP catalog uses mutable branch references, enabling remote code execution if an upstream repository is compromised.
date: "2026-08-28T21:37:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hermes:hermes_agent:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - rce
  - vulnerability
vendors:
  - Hermes
products:
  - Hermes Agent (< 0.19.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: Hermes Agent 0.18.2 prior to 0.19.0 contains a supply chain vulnerability in its bundled MCP catalog that allows a remote attacker to execute arbitrary code by compromising a third-party upstream repository referenced via a mutable branch rather than a pinned commit SHA.
    confidence_band: high
cves:
  - id: CVE-2026-82021
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82021
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Hermes Agent to 0.19.0 or later across all managed endpoints.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82021 remediation guidance.
  mitigation_plan:
    - priority: immediate
      action: Manually pin mutable branch references to specific commit SHAs in the MCP catalog configuration.
      owner: IT Operations
      addresses: CVE-2026-82021
      evidence: Source documentation on mutable branch vulnerability.
---

Hermes Agent versions 0.18.2 and earlier are susceptible to a supply chain attack involving the agent's bundled MCP catalog. The configuration relies on mutable branch names to fetch dependencies from upstream repositories rather than using pinned commit SHAs. This design choice creates a window of opportunity for attackers who compromise an upstream repository to inject malicious payloads directly into the catalog. When the Hermes Agent performs its update or installation sequence, it automatically pulls and executes the compromised code. Because this process occurs without user interaction or signature validation, the compromise can silently propagate to any host utilizing the affected catalog entry. This vulnerability poses a significant risk to environment integrity, as it facilitates remote code execution at the execution privilege level of the Hermes Agent service.

## Impact

The vulnerability allows an attacker to achieve remote code execution on any system running affected versions of Hermes Agent. By compromising an upstream dependency, the attacker gains the ability to execute arbitrary commands across the entire estate that consumes the affected catalog. This could lead to full system compromise, exfiltration of sensitive configuration data, or lateral movement within the affected network.

## Recommendation

* Upgrade all instances of Hermes Agent to version 0.19.0 or later immediately to resolve the dependency management issue.
* Audit all local MCP catalog configurations to identify and manually pin any mutable branch references to specific, verified commit SHAs until upgrades are complete.
* Implement egress filtering for systems running Hermes Agent to restrict connections only to trusted, known-good repository domains, limiting the attacker's ability to pull malicious payloads from rogue infrastructure.
* Monitor for unauthorized modifications to local MCP catalog files or unexpected network activity from the Hermes Agent process originating from package distribution sources.
