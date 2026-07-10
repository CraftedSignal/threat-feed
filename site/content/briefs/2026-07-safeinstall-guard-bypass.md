---
title: SafeInstall CLI Guard Bypass Vulnerability Allows Unauthorized Package Execution
slug: 2026-07-safeinstall-guard-bypass
description: A vulnerability in SafeInstall CLI through version 0.10.1 allows attackers to bypass its agent guard and execute unauthorized package installation or registry-provided scaffolding commands, potentially compromising developer environments.
date: "2026-07-10T19:47:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - supply-chain
  - developer-tools
  - defense-evasion
vendors:
  - SafeInstall
products:
  - safeinstall-cli
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: When the SafeInstall guard is installed for a coding agent, a crafted shell command can bypass the intended deny or ask response.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The coding agent may then run a package installation or registry-provided scaffolding command without SafeInstall policy evaluation and without SafeInstall enforcing disabled lifecycle scripts.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xrmc-c5cg-rv7x
---

A vulnerability has been identified in SafeInstall CLI versions up to 0.10.1, which impacts its agent guard's ability to properly intercept and evaluate commands. Attackers can exploit this flaw by crafting specific shell commands, which the guard fails to recognize as package-manager or registry-runner operations. This bypass is possible through techniques such as using case-variant launcher names (e.g., `nPM install`), employing leading file-descriptor redirections (e.g., `1>&2 npm install`), or utilizing supported shell wrappers with specific options (e.g., `sh -c 'npm install'`). Additionally, remote project scaffolding via package-manager `create/init` commands can also evade the guard's approval process. This allows a coding agent, influenced by an attacker, to execute malicious packages or runners without SafeInstall's policy evaluation, leading to potential compromise of local source code, credentials, and development resources with the developer's permissions. The vulnerability was discovered and remediated by the SafeInstall maintainer during adversarial parser testing.

## Attack Chain

1. An attacker gains influence or control over a developer's coding agent, potentially through social engineering, a compromised project, or a malicious dependency.
2. The attacker instructs the compromised coding agent to issue a shell command intended to execute a package installation or registry-provided scaffolding command.
3. The attacker crafts the shell command to evade the SafeInstall agent guard, utilizing methods such as case-variant launcher names (e.g., `nPM install`), leading file-descriptor redirections (e.g., `1>&2 npm install`), or supported shell wrappers with specific options (e.g., `sh -c 'npm install'`).
4. The SafeInstall agent guard, due to its parsing limitations, fails to correctly classify the crafted command as a package-manager or registry-runner invocation.
5. Consequently, the guard bypasses its intended policy evaluation and enforcement of disabled lifecycle scripts for the command.
6. The coding agent directly executes the package installation or registry-provided scaffolding command without SafeInstall's intervention.
7. A malicious package or runner is executed with the permissions of the developer's account, potentially leading to unauthorized access, data exfiltration, or further system compromise.

## Impact

Successful exploitation of this vulnerability allows a crafted shell command to bypass the SafeInstall guard's intended deny or ask response when a coding agent is in use. This enables the coding agent to execute package installation or registry-provided scaffolding commands without any policy evaluation from SafeInstall or enforcement of disabled lifecycle scripts. This direct execution, carried out with the permissions of the developer account, poses a significant risk to the confidentiality, integrity, and availability of local source code, developer credentials, and other critical development resources. The vulnerability's scope is limited to guard interception, meaning commands already routed through the SafeInstall CLI continue to receive normal policy evaluation.

## Recommendation

* Upgrade `safeinstall-cli` to version 0.10.2 or later immediately to patch the parsing vulnerabilities that allow guard bypass.
* Until an upgrade to `safeinstall-cli 0.10.2` is possible, manually review every shell command issued by coding agents and explicitly prevent them from directly invoking package managers or registry runners.
