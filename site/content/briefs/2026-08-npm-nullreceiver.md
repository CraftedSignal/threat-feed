---
title: DPRK-Linked Lazarus Group Campaign Distributing Malware via npm Packages
slug: 2026-08-npm-nullreceiver
description: The Lazarus Group is distributing malicious npm packages that use Ethereum blockchain transaction data to resolve C2 infrastructure and download secondary JavaScript payloads.
date: "2026-08-10T19:33:01Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Lazarus Group
  - HIDDEN COBRA
  - LABYRINTH CHOLLIMA
  - Diamond Sleet
  - Zinc
products:
  - '@kolbo/mcp (1.57.1)'
  - agentgui (1.0.1127)
  - godot-kit (1.0.1786316795)
  - envpack-conf (1.0.1)
  - postcss-initial-provider (3.0.4)
  - tailwindcss-motion-advanced (1.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: 'Supply Chain Compromise: Compromise Software Dependencies'
    evidence: 'Sonatype Research Labs identified six npm packages delivering the same malicious payload: three hijacked legitimate packages and three additional malicious packages.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The payload retrieved from /0x/cls can be executed directly in the current Node.js process using eval(), while downloaded stages can also be launched as detached Node.js child processes.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
    evidence: The malware uses the same Ethereum wallet address... using the NullReceiver technique to locate infrastructure hosting additional JavaScript payloads.
    confidence_band: high
references:
  - https://www.sonatype.com/blog/six-npm-packages-use-ethereum-transactions-to-retrieve-malicious-payloads
---

On August 10, 2026, Sonatype Research Labs identified six malicious npm packages associated with the DPRK-linked Contagious Interview campaign. The threat actors are using two delivery vectors: hijacking existing, trusted legitimate packages and publishing new malicious packages. Affected packages include @kolbo/mcp (1.57.1), agentgui (1.0.1127), godot-kit (1.0.1786316795), envpack-conf (1.0.1), postcss-initial-provider (3.0.4), and tailwindcss-motion-advanced (1.0.1). 

The malware employs the "NullReceiver" technique, which utilizes the Ethereum blockchain as a dead-drop mechanism to resolve C2 infrastructure. Upon execution, the loader queries Ethereum RPC providers or the Blockscout API for outbound transactions from an attacker-controlled wallet. The recipient address of the transaction is decoded into IPv4 addresses for C2 communication. The loader then retrieves secondary JavaScript payloads from /0x/cls or /0x/ls endpoints, which are decoded via Base64/XOR and executed using eval() or detached child processes. This approach ensures high resiliency in maintaining C2 connections.

## Attack Chain

1. Attacker hijacks legitimate npm package source code or publishes new packages containing a malicious loader script.
2. Victim installs the malicious package via npm, triggering the loader upon package initialization.
3. Malware queries Ethereum RPC endpoints (e.g., Infura, Alchemy) or the Blockscout API to identify a specific wallet transaction.
4. Malware reads the transaction recipient address and decodes the embedded bytes to retrieve primary and secondary C2 server IP addresses.
5. Malware performs an HTTP GET or HEAD request to the C2 infrastructure, potentially using the X-Payload-B64 header to receive an encoded payload.
6. Malware Base64-decodes and XOR-decrypts the received payload in memory.
7. Malware executes the decrypted payload using eval() within the active Node.js process or by spawning detached Node.js child processes for persistence and further staging.

## Impact

The campaign leverages trusted supply chain components to gain code execution within development and production environments. By using hijacked packages, the attackers can bypass standard dependency review processes. Successful exploitation leads to unauthorized code execution, allowing the Lazarus Group to perform data exfiltration, establish long-term persistence, or deploy further malicious stages within an organization's internal infrastructure.

## Recommendation

- Perform a recursive audit of node_modules to identify the presence of the six affected npm packages listed in this brief.
- Remove all identified packages immediately and review package-lock.json files to ensure malicious dependencies are not restored during CI/CD builds.
- Monitor network egress for unexpected queries to Ethereum RPC API providers (e.g., nodes at infura.io, alchemy.com) or blockscout.com originating from Node.js applications.
- Investigate any npm packages that contain obfuscated code or late-injected logic within existing utility files (e.g., utils.min.js or database.js).
- Implement dependency pinning and checksum verification for all npm packages to detect unauthorized modifications.
