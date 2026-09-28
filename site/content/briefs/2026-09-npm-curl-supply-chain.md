---
title: Detection of Malicious Curl Downloads during npm Package Installation
slug: 2026-09-npm-curl-supply-chain
description: Malicious npm packages and supply-chain compromises often utilize installation scripts to spawn curl processes that download secondary payloads from remote servers.
date: "2026-09-28T10:10:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
products:
  - npm (all versions)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Detects curl downloading over HTTP(S) with a short argument list, writing output to a file or launched via a shell.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The rule detects curl activity when the process ancestry includes a Node.js npm package execution.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: Malicious npm packages and supply-chain compromises commonly fetch a second stage from install or postinstall scripts.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/command_and_control_curl_download_from_npm_install.toml
  - https://www.elastic.co/blog/shai-hulud-worm-npm-supply-chain-compromise
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review endpoint logs for Node.js-based process trees initiating curl.
      owner: SOC
      due: 24h
      evidence: Source provides detection logic identifying npm-spawned curl.
  hunt_leads:
    - lead: Search for curl processes where the parent process command line contains 'npx-cli.js', 'npm-cli.js', or '.npm/_npx/'.
      technique_id: T1195.001
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Rule detection logic specifically flags these command line patterns.
---

Malicious npm packages and supply-chain compromises frequently abuse Node.js lifecycle scripts (such as `install` or `postinstall`) to fetch second-stage payloads from remote infrastructure. Attackers leverage the trust inherent in package management workflows to execute code during the `npm install` or `npx` process. This threat specifically involves the spawning of `curl` from within a Node.js process tree initiated by `npm` or `npx` CLI tools. By using short command-line arguments and standard output redirection or shell execution, these malicious scripts attempt to minimize their footprint while retrieving external malicious resources. Defenders should monitor for Node.js-originated processes that invoke curl to download remote files, as this is a high-fidelity indicator of potential dependency tampering.

## Impact

Successful exploitation allows attackers to gain arbitrary code execution within the build environment or developer workstation. This can lead to the exfiltration of sensitive environment variables, developer credentials, and project-specific API tokens, or result in the injection of persistent backdoors into build artifacts, potentially affecting downstream users of the compromised software.

## Recommendation

- Implement monitoring for child processes spawned by Node.js package managers to identify unauthorized outbound network connectivity.
- Review `package.json` lifecycle scripts for suspicious activity or obfuscated commands before executing dependency installations in CI/CD pipelines.
- Isolate build environments and restrict internet access for package manager processes, allowing only access to trusted, hardened private registries.
- Investigate any `curl` activity initiated by npm or npx process trees identified in endpoint telemetry.
