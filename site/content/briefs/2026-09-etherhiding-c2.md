---
title: Potential Etherhiding Command and Control via Blockchain Infrastructure
slug: 2026-09-etherhiding-c2
description: Adversaries are utilizing blockchain RPC endpoints as a resilient, censorship-resistant covert channel to retrieve configuration data and commands for macOS malware.
date: "2026-09-08T13:32:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - macos
  - command-and-control
  - blockchain
  - etherhiding
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: Adversaries may leverage Ethereum blockchain infrastructure as a covert C2 channel to receive commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects when a scripting interpreter makes an outbound network connection to an Ethereum blockchain endpoint.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/command_and_control_potential_etherhiding_c2.toml
  - https://secureannex.com/blog/sleepyduck-malware/
rules:
  - title: Detect Potential Etherhiding C2 via Blockchain Connection
    description: Detects when a scripting interpreter or suspicious macOS application makes an outbound connection to a blockchain RPC endpoint followed by a file modification.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1102.001
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor for blockchain RPC connections from interpreters
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Identify all outbound connections to blockchain API providers (Infura, Alchemy, etc.) from non-standard processes
      technique_id: T1102
      data_needed:
        - Network connection logs with domain resolution
      priority: high
      confidence: medium
      disposition: hunt_now
  mitigation_plan:
    - priority: medium
      action: Implement network egress filtering for blockchain API domains on non-developer subnets
      owner: Network Operations
      addresses: Blockchain API endpoints
---

The Etherhiding technique represents a sophisticated approach to command and control (C2) where threat actors store malicious payloads, configuration files, or command instructions directly within immutable blockchain transactions. By leveraging public infrastructure - such as Ethereum, Binance Smart Chain, or Polygon - attackers ensure their C2 infrastructure remains highly resilient to traditional sinkholing or takedown efforts. On macOS systems, this manifests as scripting interpreters (e.g., Python, Node.js, zsh) or specific development-oriented applications performing outbound network connections to blockchain API providers like Infura, Alchemy, or public RPC gateways. This activity, observed in campaigns such as SleepyDuck, allows attackers to dynamically reconfigure malware or fetch next-stage payloads by querying specific contract addresses, effectively blending malicious traffic with legitimate Web3 service calls.

## Attack Chain

1. Initial infection via a dropper or malicious document that installs a script or binary on the macOS endpoint.
2. The malicious process executes via a command interpreter (bash, zsh, python, node) to maintain a low footprint.
3. The script initiates a network connection to a public blockchain RPC endpoint (e.g., Infura, Alchemy, or a custom drpc.org node).
4. The script sends an API request to query a specific contract address or transaction history associated with the attacker.
5. The blockchain returns the encoded malicious configuration or payload URL embedded within the transaction data.
6. The script decodes the blockchain data and performs a file system modification (e.g., writing a new .js or .py file) to persist the retrieved instructions.
7. The malware executes the newly written configuration or payload to carry out final objectives, such as exfiltration or further system compromise.

## Impact

Successful implementation of Etherhiding allows attackers to bypass traditional domain-based C2 blocking, leading to persistent, long-term unauthorized access. This technique increases the difficulty of incident response, as the primary C2 channel is hosted on globally distributed, immutable blockchain infrastructure. Organizations may suffer from extended dwell time, covert data exfiltration, or secondary malware deployment, particularly in environments where Web3 development tools or cryptocurrency applications are common, making detection noise-heavy.

## Recommendation

1. Deploy the provided detection logic to monitor for suspicious network connections from scripting interpreters to known blockchain RPC providers.
2. Audit endpoints for the use of cryptocurrency-related tools and determine if these are sanctioned business applications.
3. Implement egress filtering at the network perimeter to restrict traffic to known-bad or unnecessary public blockchain API endpoints.
4. Monitor file system modifications in sensitive directories that align with network connections from scripting interpreters.
