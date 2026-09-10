---
title: Arbitrary Code Execution in Joker Linter via Malicious Project-Local Configuration
slug: 2026-09-joker-linter-rce
description: Joker versions before 1.8.2 are vulnerable to arbitrary code execution because the linter automatically traverses directory structures to execute project-local 'linter.*' files, allowing execution of attacker-supplied code within untrusted repositories.
date: "2026-09-10T00:51:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:candid82:joker:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - development-tools
vendors:
  - Candid82
products:
  - Joker (< 1.8.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Because these files are executable Joker/Clojure code, linting a file inside an untrusted repository could execute code supplied by that repository.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-m835-3cm9-rggg
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - DevSecOps
  immediate_actions:
    - action: Upgrade Joker to version 1.8.2 or later across all development and build environments.
      owner: IT Operations
      due: 24h
      evidence: Fixed in Joker v1.8.2.
  mitigation_plan:
    - priority: immediate
      action: Remove or audit project-local .jokerd/linter.* files in untrusted repositories.
      owner: DevSecOps
      addresses: CVE-2026-59172
      evidence: Removing or disabling project-local .jokerd/linter.* files before linting also avoids the code-execution path.
---

Joker versions before 1.8.2 are vulnerable to arbitrary code execution (CVE-2026-59172) due to insecure handling of linter configuration files. When the `joker --lint` command is executed, the application performs a directory traversal, walking up the file system from the target file to locate a `.jokerd/` directory. If found, the linter automatically executes any matching `linter.*` files (e.g., `linter.clj`, `linter.cljs`) located within that directory. Because these files contain executable Joker or Clojure code, an attacker can place malicious scripts inside a `.jokerd/` directory within a repository. If a user or automated CI/CD pipeline runs the Joker linter against files in the compromised repository, the linter will execute the attacker's code with the privileges of the user running the process. This is particularly dangerous for developers using IDE integrations that automatically trigger linters on opened or saved files.

## Attack Chain

1. Attacker identifies a target repository or project that utilizes the Joker linter for code quality checks.
2. Attacker creates a hidden directory named `.jokerd/` in the root of the repository or a subdirectory.
3. Attacker writes a malicious script into a file such as `linter.clj` within the `.jokerd/` folder.
4. Attacker submits a pull request, clones the repository, or lures a victim into opening the repository in an editor.
5. The victim or an automated CI/CD server triggers `joker --lint <target_file>` on the repository.
6. The Joker binary traverses the directory structure, identifies the malicious `.jokerd/linter.clj` file, and loads it into the interpreter.
7. The malicious code executes, resulting in unauthorized command execution under the context of the user or CI service account.

## Impact

Successful exploitation allows for arbitrary code execution on the host machine running the Joker linter. This impacts developers, build servers, and automated linting environments. Attackers can leverage this to gain initial access to development environments, exfiltrate environment variables, compromise CI pipelines, or move laterally within a development infrastructure.

## Recommendation

Prioritized actions for detection and remediation:
- Upgrade Joker to version 1.8.2 or later immediately to restrict linter configuration loading to the user-specific `~/.jokerd/` directory.
- Implement a policy in CI/CD environments to audit or block repositories containing `.jokerd/` directories if they are not explicitly managed by the organization.
- Deploy detection rules to identify command-line executions of `joker --lint` that coincide with unexpected file system access to `.jokerd` subdirectories in application project paths.
- Prioritize patching CVE-2026-59172 on all build servers and developer workstations where Joker is utilized.
