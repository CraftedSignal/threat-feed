---
title: Evomap Evolver Validator RCE via NPM/NPX in Sandbox Allowlist
slug: 2024-01-evomap-rce
description: The validator-mode sandbox executor in @evomap/evolver versions 1.70.0-beta.4 and earlier places `npm` and `npx` in its executable allowlist, allowing arbitrary code execution because validator nodes consume unsigned Hub responses without signature checks, leading to remote code execution on every validator node via lifecycle scripts.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - sandbox-escape
  - npm
  - npx
  - supply-chain
vendors:
  - npm
products:
  - '@evomap/evolver (<= 1.70.0-beta.4)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-jxh8-jh77-xh6g
rules:
  - title: Detect NPM Install from Unusual Processes
    description: Detects npm install commands executed from unusual parent processes, potentially indicating exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect NPX Execution from Unusual Processes
    description: Detects npx commands executed from unusual parent processes, potentially indicating exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A vulnerability exists in the @evomap/evolver package, specifically affecting versions up to 1.70.0-beta.4. The flaw stems from the inclusion of `npm` and `npx` in the validator-mode sandbox executor's allowlist. This oversight permits an attacker who compromises or intercepts communications with the Hub to achieve remote code execution (RCE) on every validator node. The issue arises because the `validation_commands` strings fetched from the Hub are not subject to signature verification before being passed to the sandbox. The vulnerability has been present since validator mode was enabled by default in v1.69.0. Attackers can exploit this by injecting malicious commands through the Hub, leveraging `npm` and `npx` to execute arbitrary code via lifecycle scripts or remote package execution. This poses a significant risk to the integrity and security of validator nodes within the evolver network.

## Attack Chain

1. The validator node POSTs a request to the Hub's `/a2a/fetch` endpoint to retrieve `validation_tasks`.
2. The Hub responds with a JSON payload containing a `validation_tasks` array, including `task.validation_commands` strings, without signature verification.
3. The validator extracts the `task.validation_commands` array (controlled by the attacker) and passes it to `runInSandbox`.
4. `runInSandbox` processes each command in the array, checking against `ALLOWED_EXECUTABLES` which includes `npm` and `npx`.
5. When `npm` or `npx` commands are present, they bypass `assertNodeCommandSafe`, which would normally block dangerous Node.js flags.
6. The `npm` command, such as `npm install <malicious_package>`, is executed, triggering the package's `preinstall`, `install`, and `postinstall` scripts. Alternatively, `npx` can be used to fetch and execute a remote package's `bin` entry.
7. These scripts execute arbitrary code within the validator process's context, enabling the attacker to perform malicious actions.
8. The validator continues its normal operations, polling the Hub every 60 seconds, potentially re-triggering the exploit with updated malicious commands.

## Impact

Successful exploitation leads to arbitrary code execution as the evolver/validator process UID on every validator node that communicates with a compromised Hub, which occurs by default every 60 seconds. This can result in the exfiltration of sensitive credentials, including HUB_NODE_SECRET and A2A node identity. Furthermore, attackers can achieve persistence by writing to cron jobs, systemd units, or shell RC files and potentially pivot into the host's container or VM. Due to the default-on validator mode since v1.69.0, the vulnerability is wormable across the network, as a single Hub compromise can auto-RCE every node. The compromised Hub can also lead to denial of service.

## Recommendation

- Immediately remove `npm` and `npx` from the `ALLOWED_EXECUTABLES` list in `src/gep/validator/sandboxExecutor.js` as shown in the advisory.
- Implement signature verification for the Hub's `/a2a/fetch` response to prevent MITM attacks, as described in the advisory.
- Deploy the Sigma rule "Detect NPM Install from Unusual Processes" to identify potential exploitation attempts using `npm install` commands originating from unexpected parent processes.
- Deploy the Sigma rule "Detect NPX Execution from Unusual Processes" to identify potential exploitation attempts using `npx` commands originating from unexpected parent processes.
